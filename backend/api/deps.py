"""Shared dependencies and singletons for the API layer.

Anything that used to be a module-level global in ``main.py`` and that needs
to be reused across multiple routers lives here:

- ``limiter``         : the SlowAPI rate-limiter
- ``orchestrator``    : the SimulationOrchestrator singleton
- ``PROJECT_ROOT``    : repo root path (for safe-path checks)
- ``_rate_limit_key`` : tenant-aware rate-limit key (tenant:user or IP)
- ``_client_ip``      : extract the real client IP from request headers
- ``_get_cached_result`` : fetch a cached simulation result or raise 404
- ``result_cache_key`` : tenant-scoped simulation result cache key
- ``_safe_path``      : prevent path-traversal in user-supplied filenames
- ``_SAFE_ID_RE``     : whitelist regex used by ``_safe_path``
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path

from fastapi import HTTPException, Request
from slowapi import Limiter

import jwt as _jwt

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.cache import cache  # noqa: E402  (import after sys.path tweak)
from backend.orchestrator import SimulationOrchestrator  # noqa: E402

_logger = logging.getLogger("cybertwin.deps")

# ---------------------------------------------------------------------------
# Rate-limit key: tenant-aware with JWT username fallback to IP
# ---------------------------------------------------------------------------


def _rate_limit_key(request: Request) -> str:
    """Build a per-tenant, per-user rate-limit key.

    Priority:
      1. tenant_id from ``request.state`` (set by TenantScopeMiddleware)
      2. Falls back to client IP when tenant_id is unavailable.
    The second segment is the JWT ``sub`` claim (username) when present,
    otherwise the client IP address.
    """
    tenant_id: str | None = getattr(request.state, "tenant_id", None)

    username: str | None = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            from backend.auth import JWT_SECRET, JWT_ALGORITHM
            payload = _jwt.decode(
                auth_header[7:],
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False},
            )
            username = payload.get("sub")
        except Exception:
            pass

    ip = _client_ip(request)
    identity = username or ip
    if tenant_id:
        return f"{tenant_id}:{identity}"
    return identity


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

_RATE_LIMIT_STORAGE_URI = os.getenv("RATE_LIMIT_STORAGE_URI") or os.getenv("REDIS_URL")
limiter = Limiter(
    key_func=_rate_limit_key,
    storage_uri=_RATE_LIMIT_STORAGE_URI,
    in_memory_fallback_enabled=True,
)
orchestrator = SimulationOrchestrator()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


def _client_ip(request: Request) -> str:
    """Return the best-effort client IP, honouring ``X-Forwarded-For``."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def result_cache_key(scenario_id: str, tenant_id: str = "default") -> str:
    """Return the tenant-scoped cache key for a simulation result."""
    return f"result:{tenant_id}:{scenario_id}"


def _get_cached_result(scenario_id: str, *, tenant_id: str = "default") -> dict:
    """Return the tenant-scoped cached simulation result or raise 404."""
    result = cache.get(result_cache_key(scenario_id, tenant_id))
    if result is None:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return result


def _safe_path(base: Path, name: str, suffix: str) -> Path:
    """Compose ``base / (name + suffix)`` while guaranteeing the resolved
    path stays inside ``base``. Raises HTTP 400 on any traversal attempt.
    """
    if not _SAFE_ID_RE.match(name):
        raise HTTPException(400, "Invalid identifier")
    candidate = (base / f"{name}{suffix}").resolve()
    base_resolved = base.resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise HTTPException(400, "Invalid path") from exc
    return candidate
