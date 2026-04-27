"""Shared dependencies and singletons for the API layer.

Anything that used to be a module-level global in ``main.py`` and that needs
to be reused across multiple routers lives here:

- ``limiter``         : the SlowAPI rate-limiter
- ``orchestrator``    : the SimulationOrchestrator singleton
- ``PROJECT_ROOT``    : repo root path (for safe-path checks)
- ``_client_ip``      : extract the real client IP from request headers
- ``_get_cached_result`` : fetch a cached simulation result or raise 404
- ``_safe_path``      : prevent path-traversal in user-supplied filenames
- ``_SAFE_ID_RE``     : whitelist regex used by ``_safe_path``
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fastapi import HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.cache import cache  # noqa: E402  (import after sys.path tweak)
from backend.orchestrator import SimulationOrchestrator  # noqa: E402

# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)
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


def _get_cached_result(scenario_id: str) -> dict:
    """Return the cached simulation result for ``scenario_id`` or raise 404."""
    result = cache.get(f"result:{scenario_id}")
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
