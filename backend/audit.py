"""
CyberTwin SOC — Audit Logging Module
======================================
Records every security-relevant action (logins, simulation runs,
deletions, configuration changes) to a dedicated SQLite audit table
and to the application logger.

Phase 3.1 additions:
  - ORM writes via SQLAlchemy when DATABASE_URL is set (PostgreSQL mode)
  - Tamper-evident hash chain (SHA-256, previous_hash:entry_data)
  - Hash chain verification for forensic integrity audits
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cybertwin.audit")

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybertwin.db"

_GENESIS_HASH = "0" * 64
_REDIS_HASH_KEY = "cybertwin:audit:last_hash"


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _compute_hash(previous_hash: str, entry_data: str) -> str:
    return hashlib.sha256(f"{previous_hash}:{entry_data}".encode()).hexdigest()


def _get_last_hash() -> str:
    """Retrieve the last hash from Redis (fast path) or fall back to DB scan."""
    try:
        from backend.cache import cache
        cached = cache.get(_REDIS_HASH_KEY)
        if cached:
            return cached
    except Exception:
        pass
    return _GENESIS_HASH


def _store_last_hash(h: str) -> None:
    """Persist the latest hash to Redis for fast chain continuation."""
    try:
        from backend.cache import cache
        cache.set(_REDIS_HASH_KEY, h)
    except Exception:
        pass


def _database_url_set() -> bool:
    url = os.getenv("DATABASE_URL", "")
    return bool(url) and not url.startswith("sqlite")


def _write_to_orm(
    ts: str,
    username: str,
    role: str,
    action: str,
    resource: Optional[str],
    ip_address: Optional[str],
    status: str,
    details_json: Optional[str],
    integrity_hash: str,
) -> None:
    """Write an audit record via the SQLAlchemy ORM (PostgreSQL mode)."""
    from backend.db.session import SessionLocal
    from backend.db.models import AuditLog

    session = SessionLocal()
    try:
        entry = AuditLog(
            timestamp=datetime.fromisoformat(ts),
            tenant_id="default",
            username=username,
            role=role,
            action=action,
            resource=resource,
            ip_address=ip_address,
            status=status,
            details=json.loads(details_json) if details_json else None,
            integrity_hash=integrity_hash,
        )
        session.add(entry)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_audit_table() -> None:
    """Create the audit_log table and its indexes if missing.

    Indexes are essential for compliance/forensic queries:
    - filtering by user (incident response, insider-threat investigations)
    - filtering by action (e.g. "every CASE_CLOSE in the last 30 days")
    - time-window queries (SOX, GDPR access reviews)
    - failure tracking (status='failure' for brute-force forensics)
    """
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
            details     TEXT,
            integrity_hash TEXT
        )
    """)
    # Add integrity_hash column to existing tables that lack it
    try:
        conn.execute("ALTER TABLE audit_log ADD COLUMN integrity_hash TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_timestamp "
        "ON audit_log (timestamp DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_username_id "
        "ON audit_log (username, id DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_action "
        "ON audit_log (action)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_audit_status "
        "ON audit_log (status) WHERE status != 'success'"
    )
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
    ts = datetime.now(timezone.utc).isoformat()
    details_json = json.dumps(details, default=str) if details else None

    entry_data = f"{ts}|{username}|{role}|{action}|{resource}|{ip_address}|{status}|{details_json}"
    previous_hash = _get_last_hash()
    integrity_hash = _compute_hash(previous_hash, entry_data)

    written = False

    if _database_url_set():
        try:
            _write_to_orm(
                ts, username, role, action, resource,
                ip_address, status, details_json, integrity_hash,
            )
            written = True
        except Exception as exc:
            logger.warning("ORM audit write failed, falling back to SQLite: %s", exc)

    if not written:
        try:
            conn = _conn()
            conn.execute(
                """INSERT INTO audit_log
                   (timestamp, username, role, action, resource, ip_address, status, details, integrity_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, username, role, action, resource, ip_address, status, details_json, integrity_hash),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.error("Audit DB write failed: %s", exc)

    _store_last_hash(integrity_hash)

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


def verify_audit_chain(limit: int = 1000) -> dict[str, Any]:
    """Verify the integrity of the last *limit* audit entries.

    Reads entries in chronological order (oldest first within the window),
    recomputes each hash from its predecessor, and checks for breaks.

    Returns a dict with:
      - valid: bool — True if the entire chain is intact
      - checked: int — number of entries verified
      - first_broken_id: int | None — the id of the first tampered entry
      - message: str — human-readable summary
    """
    if _database_url_set():
        return _verify_chain_orm(limit)
    return _verify_chain_sqlite(limit)


def _verify_chain_sqlite(limit: int) -> dict[str, Any]:
    conn = _conn()
    rows = conn.execute(
        "SELECT id, timestamp, username, role, action, resource, "
        "ip_address, status, details, integrity_hash "
        "FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return _verify_rows([dict(r) for r in reversed(rows)])


def _verify_chain_orm(limit: int) -> dict[str, Any]:
    from backend.db.session import SessionLocal
    from backend.db.models import AuditLog

    session = SessionLocal()
    try:
        rows = (
            session.query(AuditLog)
            .order_by(AuditLog.id.desc())
            .limit(limit)
            .all()
        )
        entries = []
        for r in reversed(rows):
            entries.append({
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                "username": r.username,
                "role": r.role,
                "action": r.action,
                "resource": r.resource,
                "ip_address": r.ip_address,
                "status": r.status,
                "details": json.dumps(r.details, default=str) if r.details else None,
                "integrity_hash": r.integrity_hash,
            })
        return _verify_rows(entries)
    finally:
        session.close()


def _verify_rows(entries: list[dict]) -> dict[str, Any]:
    """Core chain verification logic shared by SQLite and ORM paths."""
    if not entries:
        return {"valid": True, "checked": 0, "first_broken_id": None,
                "message": "No audit entries to verify"}

    previous_hash = _GENESIS_HASH
    for entry in entries:
        stored_hash = entry.get("integrity_hash")
        if not stored_hash:
            previous_hash = _GENESIS_HASH
            continue

        details_raw = entry.get("details")
        if details_raw and not isinstance(details_raw, str):
            details_raw = json.dumps(details_raw, default=str)

        ts = entry.get("timestamp", "")
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()

        entry_data = (
            f"{ts}|{entry.get('username')}|{entry.get('role')}|"
            f"{entry.get('action')}|{entry.get('resource')}|"
            f"{entry.get('ip_address')}|{entry.get('status')}|{details_raw}"
        )
        expected = _compute_hash(previous_hash, entry_data)
        if expected != stored_hash:
            return {
                "valid": False,
                "checked": entries.index(entry) + 1,
                "first_broken_id": entry.get("id"),
                "message": f"Hash chain broken at entry id={entry.get('id')}",
            }
        previous_hash = stored_hash

    return {
        "valid": True,
        "checked": len(entries),
        "first_broken_id": None,
        "message": f"All {len(entries)} entries verified — chain intact",
    }
