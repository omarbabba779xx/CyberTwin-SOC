"""Structured JSON logging with request_id correlation.

Activates only when ENABLE_JSON_LOGS=1 in the environment so local
development keeps the human-readable format.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

from .middleware import request_id_var


class JsonFormatter(logging.Formatter):
    """Minimal RFC 5424-aware JSON log line formatter."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Carry over extras that don't conflict with built-ins
        for k, v in record.__dict__.items():
            if k in payload or k.startswith("_") or k in {
                "args", "msg", "msecs", "relativeCreated", "created",
                "exc_info", "exc_text", "stack_info", "levelno", "levelname",
                "name", "pathname", "filename", "module", "funcName",
                "lineno", "thread", "threadName", "process", "processName",
                "message",
            }:
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except TypeError:
                payload[k] = str(v)
        return json.dumps(payload, default=str)


def setup_json_logging(level: str = "INFO") -> None:
    """Replace stdlib logging handlers with a JSON formatter on stdout."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def auto_configure() -> None:
    """Call setup_json_logging() if ENABLE_JSON_LOGS is truthy."""
    flag = os.getenv("ENABLE_JSON_LOGS", "").lower()
    if flag in ("1", "true", "yes", "on"):
        setup_json_logging(os.getenv("LOG_LEVEL", "INFO"))
