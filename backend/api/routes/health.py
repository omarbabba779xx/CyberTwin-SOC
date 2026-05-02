"""Health, root, and Prometheus metrics endpoints.

``/api/health``       — public, probed by Docker/K8s liveness.
``/api/health/deep``  — optional auth via RESTRICT_INTERNAL_ENDPOINTS=true.
``/api/metrics``      — optional auth via RESTRICT_INTERNAL_ENDPOINTS=true.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from backend.auth import has_permission_for_tenant, verify_token_optional
from backend.cache import cache

from ..deps import limiter

logger = logging.getLogger("cybertwin.health")

router = APIRouter(tags=["health"])


def _internal_access(user=Depends(verify_token_optional)):
    """Require auth for internal endpoints when RESTRICT_INTERNAL_ENDPOINTS=true."""
    if os.getenv("RESTRICT_INTERNAL_ENDPOINTS", "false").lower() != "true":
        return None

    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    role = user.get("role", "viewer")
    tenant_id = user.get("tenant_id") or "default"
    if not has_permission_for_tenant(role, "view_results", tenant_id):
        raise HTTPException(status_code=403, detail="Permission 'view_results' required")
    return user


@router.get("/")
@limiter.limit("60/minute")
def root(request: Request):
    return {
        "name": "CyberTwin SOC API",
        "version": os.getenv("APP_VERSION", "3.0.0"),
        "status": "running",
        "cache": cache.backend,
    }


@router.get("/api/health")
@limiter.limit("120/minute")
def health(request: Request):
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/api/health/deep")
@limiter.limit("60/minute")
def health_deep(request: Request, _user=Depends(_internal_access)):
    """Deep health probe: report dependency status (cache, DB, ingestion).

    Set RESTRICT_INTERNAL_ENDPOINTS=true to require authentication.
    In Kubernetes, expose this only inside the cluster (ClusterIP / readiness probe).
    """
    checks: dict[str, dict] = {}

    # -- Redis PING (direct client check, independent of cache layer) -------
    try:
        import redis as _redis

        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            t0 = time.monotonic()
            client = _redis.from_url(redis_url, socket_connect_timeout=2)
            client.ping()
            latency = round((time.monotonic() - t0) * 1000, 2)
            checks["redis"] = {"status": "ok", "latency_ms": latency}
        else:
            checks["redis"] = {"status": "skipped", "reason": "REDIS_URL not set"}
    except ImportError:
        checks["redis"] = {"status": "skipped", "reason": "redis package not installed"}
    except Exception as exc:
        logger.warning("Redis health check failed: %s", exc)
        checks["redis"] = {"status": "degraded", "error": str(exc)}

    # -- PostgreSQL / SQLAlchemy check --------------------------------------
    database_url = os.getenv("DATABASE_URL", "")
    if database_url:
        try:
            from sqlalchemy import create_engine, text

            t0 = time.monotonic()
            engine = create_engine(database_url, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            latency = round((time.monotonic() - t0) * 1000, 2)
            checks["database"] = {"status": "ok", "latency_ms": latency}
        except ImportError:
            checks["database"] = {"status": "skipped", "reason": "sqlalchemy not installed"}
        except Exception as exc:
            logger.warning("PostgreSQL health check failed: %s", exc)
            checks["database"] = {"status": "degraded", "error": str(exc)}
    else:
        # Fall back to the existing SQLite stats check
        try:
            from backend.database import get_stats

            t0 = time.monotonic()
            get_stats()
            latency = round((time.monotonic() - t0) * 1000, 2)
            checks["database"] = {"status": "ok", "latency_ms": latency}
        except Exception as exc:
            logger.warning("Database health check failed: %s", exc)
            checks["database"] = {"status": "degraded", "error": str(exc)}

    # -- Cache layer --------------------------------------------------------
    try:
        cache.set("__health__", "ok", ttl=10) if hasattr(cache, "set") else None
        checks["cache"] = {"status": "ok", "backend": cache.backend}
    except Exception as exc:
        checks["cache"] = {"status": "degraded", "error": str(exc)}

    # -- Ingestion pipeline -------------------------------------------------
    try:
        from backend.ingestion import get_pipeline

        pipe = get_pipeline()
        checks["ingestion"] = {
            "status": "ok",
            "buffer_size": pipe.buffer_size(),
            "events_total": pipe.stats.total_events_received,
        }
    except Exception as exc:
        checks["ingestion"] = {"status": "degraded", "error": str(exc)}

    overall = (
        "ok"
        if all(c["status"] in ("ok", "skipped") for c in checks.values())
        else "degraded"
    )
    body = {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": os.getenv("APP_VERSION", "3.0.0"),
        "checks": checks,
    }
    return JSONResponse(body, status_code=200 if overall == "ok" else 503)


@router.get("/api/metrics")
@limiter.limit("60/minute")
def metrics_endpoint(request: Request, _user=Depends(_internal_access)):
    """Prometheus exposition format.

    Set RESTRICT_INTERNAL_ENDPOINTS=true to require authentication.
    In production, restrict this path to your Prometheus scraper network/IP.
    """
    from backend.observability.metrics import render_metrics
    body, content_type = render_metrics()
    return Response(body, media_type=content_type)
