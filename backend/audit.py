"""
CyberTwin SOC — Audit Logging Module
======================================
Records every security-relevant action (logins, simulation runs,
deletions, configuration changes) to a dedicated SQLite audit table
and to the application logger.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cybertwin.audit")

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybertwin.db"


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_table() -> None:
    """Create the audit_log table if it does not exist."""
    conn = _conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            username    TEXT    NOT NULL DEFAULT 'anonymous',
            role        TEXT    NOT NULL DEFAULT 'unknown',
            action      TEXT    NOT NULL,
            resource    TEXT,
            ip_address  TEXT,
            status      TEXT    NOT NULL DEFAULT 'success',
            details     TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_action(
    action: str,
    username: str = "anonymous",
    role: str = "unknown",
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    details: Optional[dict[str, Any]] = None,
) -> None:
    """Write one audit record to the database and application log."""
    ts = datetime.utcnow().isoformat()
    details_json = json.dumps(details, default=str) if details else None

    try:
        conn = _conn()
        conn.execute(
            """INSERT INTO audit_log
               (timestamp, username, role, action, resource, ip_address, status, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, username, role, action, resource, ip_address, status, details_json),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.error("Audit DB write failed: %s", exc)

    log_level = logging.WARNING if status == "failure" else logging.INFO
    logger.log(
        log_level,
        "AUDIT | user=%-12s role=%-8s action=%-30s resource=%s status=%s",
        username, role, action, resource or "-", status,
    )


def get_audit_log(limit: int = 200, username: Optional[str] = None) -> list[dict]:
    """Return recent audit records, optionally filtered by username."""
    conn = _conn()
    if username:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE username=? ORDER BY id DESC LIMIT ?",
            (username, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        result.append(d)
    return result
