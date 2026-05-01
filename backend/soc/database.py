"""SOC module persistence layer.

The workflow store keeps a SQLite-compatible operational path for local
use and creates the ORM schema when ``DATABASE_URL`` is set. All runtime
queries are tenant-scoped so local/demo mode no longer leaks SOC objects
between tenants.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger("cybertwin.soc.database")

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "cybertwin.db"


def use_orm() -> bool:
    """Return True when SOC runtime should use SQLAlchemy DATABASE_URL."""
    return bool(os.getenv("DATABASE_URL", "").strip())


# ---------------------------------------------------------------------------
# SQLite helpers (legacy fallback)
# ---------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    """Open a SQLite connection with row_factory and FK enforcement."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}  # nosec B608
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")  # nosec B608


def _sqlite_init_tables() -> None:
    conn = get_conn()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_feedback (
            feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id   TEXT NOT NULL DEFAULT 'default',
            alert_id    TEXT NOT NULL,
            rule_id     TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            reason      TEXT,
            analyst     TEXT NOT NULL,
            role        TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        )
    """)
    _ensure_column(conn, "alert_feedback", "tenant_id", "tenant_id TEXT NOT NULL DEFAULT 'default'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_rule ON alert_feedback(rule_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_alert ON alert_feedback(alert_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_tenant_rule ON alert_feedback(tenant_id, rule_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_tenant_alert ON alert_feedback(tenant_id, alert_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_cases (
            case_id        TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL DEFAULT 'default',
            title          TEXT NOT NULL,
            description    TEXT,
            severity       TEXT NOT NULL,
            status         TEXT NOT NULL,
            assignee       TEXT,
            created_by     TEXT NOT NULL,
            created_at     TEXT NOT NULL,
            updated_at     TEXT NOT NULL,
            closed_at      TEXT,
            closure_reason TEXT,
            sla_due_at     TEXT,
            alert_ids      TEXT DEFAULT '[]',
            incident_ids   TEXT DEFAULT '[]',
            affected_hosts TEXT DEFAULT '[]',
            affected_users TEXT DEFAULT '[]',
            mitre_techniques TEXT DEFAULT '[]',
            tags           TEXT DEFAULT '[]'
        )
    """)
    _ensure_column(conn, "soc_cases", "tenant_id", "tenant_id TEXT NOT NULL DEFAULT 'default'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_status ON soc_cases(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_severity ON soc_cases(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_assignee ON soc_cases(assignee)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_tenant_status ON soc_cases(tenant_id, status)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_tenant_severity ON soc_cases(tenant_id, severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_tenant_assignee ON soc_cases(tenant_id, assignee)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_comments (
            comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL,
            tenant_id  TEXT NOT NULL DEFAULT 'default',
            author     TEXT NOT NULL,
            role       TEXT NOT NULL,
            body       TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE
        )
    """)
    _ensure_column(conn, "case_comments", "tenant_id", "tenant_id TEXT NOT NULL DEFAULT 'default'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_comments_case ON case_comments(case_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_comments_tenant_case ON case_comments(tenant_id, case_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL,
            tenant_id   TEXT NOT NULL DEFAULT 'default',
            type        TEXT NOT NULL,
            reference   TEXT NOT NULL,
            description TEXT,
            added_by    TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            payload     TEXT,
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE
        )
    """)
    _ensure_column(conn, "case_evidence", "tenant_id", "tenant_id TEXT NOT NULL DEFAULT 'default'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_case ON case_evidence(case_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_tenant_case ON case_evidence(tenant_id, case_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS suppressions (
            suppression_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id      TEXT NOT NULL DEFAULT 'default',
            scope          TEXT NOT NULL,
            target         TEXT NOT NULL,
            reason         TEXT NOT NULL,
            created_by     TEXT NOT NULL,
            created_at     TEXT NOT NULL,
            expires_at     TEXT NOT NULL,
            active         INTEGER NOT NULL DEFAULT 1,
            approved_by    TEXT
        )
    """)
    _ensure_column(conn, "suppressions", "tenant_id", "tenant_id TEXT NOT NULL DEFAULT 'default'")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_scope ON suppressions(scope, active)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_expires ON suppressions(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_tenant_scope ON suppressions(tenant_id, scope, active)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_tenant_expires ON suppressions(tenant_id, expires_at)")

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# ORM helpers (PostgreSQL production path)
# ---------------------------------------------------------------------------

def _orm_init_tables() -> None:
    from backend.db.models import Base
    from backend.db.session import engine
    Base.metadata.create_all(bind=engine)
    logger.info("SOC ORM tables ensured via SQLAlchemy")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_soc_tables() -> None:
    """Create all SOC tables if they don't exist (idempotent)."""
    if use_orm():
        _orm_init_tables()
        return
    _sqlite_init_tables()
