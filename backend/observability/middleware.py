"""Request-ID correlation middleware (X-Request-ID)."""

from __future__ import annotations

import contextvars
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Async-safe context variable so loggers can access the current request_id.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default=""
)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request_id to each incoming request.

    Honors any incoming `X-Request-ID` header (for tracing across hops),
    otherwise generates a UUID4. The id is exposed on the response and on
    the contextvar so loggers can include it.
    """

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        token = request_id_var.set(rid)
        try:
            response: Response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response
