"""Tenant scope middleware — extracts tenant_id from JWT and injects into request state."""

from __future__ import annotations

import logging

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from backend.auth import JWT_SECRET, JWT_ALGORITHM

logger = logging.getLogger("cybertwin.middleware.tenant")


class TenantScopeMiddleware(BaseHTTPMiddleware):
    """Extract tenant_id from the Authorization JWT and attach to request.state.

    Falls back to "default" if no token is present or decoding fails.
    This middleware never blocks requests — it only enriches request state.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        tenant_id = "default"

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                tenant_id = payload.get("tenant_id", "default")
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
            except Exception:
                logger.debug("Unexpected error decoding JWT for tenant extraction", exc_info=True)

        request.state.tenant_id = tenant_id
        return await call_next(request)
