"""Unified error response envelope for all API errors.

Format::

    {"error": {"code": "...", "message": "...", "request_id": "...", "timestamp": "..."}}

Every exception that inherits from ``CyberTwinError`` is automatically
serialised into this envelope by the global handlers registered in
``main.py``.  ``HTTPException`` and unhandled ``Exception`` are wrapped
in the same shape so clients always see a single schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from backend.observability.middleware import request_id_var

# ---------------------------------------------------------------------------
# Error codes (constants)
# ---------------------------------------------------------------------------

RATE_LIMITED: str = "RATE_LIMITED"
UNAUTHORIZED: str = "UNAUTHORIZED"
FORBIDDEN: str = "FORBIDDEN"
NOT_FOUND: str = "NOT_FOUND"
VALIDATION_ERROR: str = "VALIDATION_ERROR"
INTERNAL_ERROR: str = "INTERNAL_ERROR"
TASK_NOT_FOUND: str = "TASK_NOT_FOUND"
SCENARIO_NOT_FOUND: str = "SCENARIO_NOT_FOUND"


# ---------------------------------------------------------------------------
# Exception class
# ---------------------------------------------------------------------------

class CyberTwinError(Exception):
    """Base application error that maps to a structured JSON envelope."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


# ---------------------------------------------------------------------------
# Response builder
# ---------------------------------------------------------------------------

def error_response(
    *,
    code: str,
    message: str,
    status_code: int = 500,
    details: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> JSONResponse:
    """Build a ``JSONResponse`` with the canonical error envelope.

    ``request_id`` is pulled from the context variable set by
    ``RequestIdMiddleware``; passing *request* is accepted for
    forward-compatibility but not currently required.
    """
    body: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": request_id_var.get() or None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if details:
        body["details"] = details
    return JSONResponse(status_code=status_code, content={"error": body})
