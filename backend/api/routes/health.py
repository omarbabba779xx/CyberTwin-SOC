"""Health, root, and Prometheus metrics endpoints.

``/api/health``       — public, probed by Docker/K8s liveness.
``/api/health/deep``  — optional auth via RESTRICT_INTERNAL_ENDPOINTS=true.
``/api/metrics``      — optional auth via RESTRICT_INTERNAL_ENDPOINTS=true.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from backend.cache import cache

from ..deps import limiter

router = APIRouter(tags=["health"])

_restrict_internals = os.getenv("RESTRICT_INTERNAL_ENDPOINTS", "false").lower() == "true"


def _maybe_require_auth():
    """Return an auth dependency when RESTRICT_INTERNAL_ENDPOINTS=true, else None."""
    if _restrict_internals:
        from backend.auth import require_permission
        return Depends(require_permission("view_results"))
    return None


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
def health_deep(request: Request):
    """Deep health probe: report dependency status (cache, DB, ingestion).

    Set RESTRICT_INTERNAL_ENDPOINTS=true to require authentication.
    In Kubernetes, expose this only inside the cluster (ClusterIP / readiness probe).
    """
    checks: dict[str, dict] = {}

    try:
        cache.set("__health__", "ok", ttl=10) if hasattr(cache, "set") else None
        checks["cache"] = {"status": "ok", "backend": cache.backend}
    except Exception as exc:
        checks["cache"] = {"status": "degraded", "error": str(exc)}

    try:
        from backend.database import get_stats
        get_stats()
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        checks["database"] = {"status": "degraded", "error": str(exc)}

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

    overall = "ok" if all(c["status"] == "ok" for c in checks.values()) else "degraded"
    body = {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": os.getenv("APP_VERSION", "3.0.0"),
        "checks": checks,
    }
    return JSONResponse(body, status_code=200 if overall == "ok" else 503)


@router.get("/api/metrics")
@limiter.limit("60/minute")
def metrics_endpoint(request: Request):
    """Prometheus exposition format.

    Set RESTRICT_INTERNAL_ENDPOINTS=true to require authentication.
    In production, restrict this path to your Prometheus scraper network/IP.
    """
    from backend.observability.metrics import render_metrics
    body, content_type = render_metrics()
    return Response(body, media_type=content_type)
