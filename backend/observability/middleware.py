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


def _otel_trace_id() -> str | None:
    """Return the active OTel trace ID when tracing is enabled, else None."""
    try:
        from backend.observability.tracing import get_current_trace_id
        return get_current_trace_id()
    except Exception:
        return None


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request_id to each incoming request.

    Honors any incoming ``X-Request-ID`` header (for tracing across hops).
    When OpenTelemetry tracing is active the OTel trace ID is used instead
    of a random UUID so distributed traces and request logs correlate
    automatically.  Falls back to UUID4 when OTel is not running.
    """

    async def dispatch(self, request: Request, call_next):
        rid = (
            request.headers.get("X-Request-ID")
            or _otel_trace_id()
            or uuid.uuid4().hex
        )
        token = request_id_var.set(rid)
        try:
            response: Response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response
