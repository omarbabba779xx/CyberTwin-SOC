"""HTTP security headers middleware.

Applied to every response so that:

- The browser refuses to render the page in an iframe (clickjacking).
- The browser refuses to MIME-sniff text/plain into JS / CSS.
- Referrer leakage is bounded.
- HSTS is set when running behind HTTPS (driven by the inbound scheme).
- A strict CSP keeps cross-origin inline scripts out of the SPA.

The CSP is intentionally permissive for ``/docs`` (Swagger UI loads its
own bundle) and ``/redoc``; everywhere else it locks down to the same
origin and the configured backend.
"""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# When developers run the full stack on http://localhost we cannot enforce
# HSTS; it is only emitted when the request actually arrived on HTTPS
# (forwarded from a TLS-terminating proxy).
_DEFAULT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# Strict CSP for API responses. Swagger UI (/docs) needs more permissive
# rules; we relax CSP only on those paths.
_API_CSP = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)
_DOCS_CSP = (
    "default-src 'self'; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "font-src 'self' data:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security-relevant response headers on every request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Static defaults
        for name, value in _DEFAULT_HEADERS.items():
            response.headers.setdefault(name, value)

        # CSP: lighter on Swagger / ReDoc, strict everywhere else.
        path = request.url.path
        if path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers.setdefault("Content-Security-Policy", _DOCS_CSP)
        else:
            response.headers.setdefault("Content-Security-Policy", _API_CSP)

        # HSTS only over real HTTPS — never on localhost dev.
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        if scheme == "https" and os.getenv("ENV", "dev").lower() == "production":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )

        # Drop the FastAPI server banner — small fingerprinting hygiene.
        if "server" in response.headers:
            del response.headers["server"]
        return response
