"""SQLite persistence helpers for the SOC module.

We extend the existing `data/cybertwin.db` rather than introducing a new
database file. Every table is created idempotently by `init_soc_tables()`.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "cybertwin.db"


def get_conn() -> sqlite3.Connection:
    """Open a connection with row_factory and FK enforcement."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_soc_tables() -> None:
    """Create all SOC tables if they don't exist (idempotent)."""
    conn = get_conn()

    # -- Alert feedback ----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_feedback (
            feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    TEXT NOT NULL,
            rule_id     TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            reason      TEXT,
            analyst     TEXT NOT NULL,
            role        TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_rule ON alert_feedback(rule_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_feedback_alert ON alert_feedback(alert_id)")

    # -- Cases -------------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS soc_cases (
            case_id        TEXT PRIMARY KEY,
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
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_status ON soc_cases(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_severity ON soc_cases(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cases_assignee ON soc_cases(assignee)")

    # -- Case comments -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_comments (
            comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id    TEXT NOT NULL,
            author     TEXT NOT NULL,
            role       TEXT NOT NULL,
            body       TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_comments_case ON case_comments(case_id)")

    # -- Case evidence -----------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_evidence (
            evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL,
            type        TEXT NOT NULL,
            reference   TEXT NOT NULL,
            description TEXT,
            added_by    TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            payload     TEXT,
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_evidence_case ON case_evidence(case_id)")

    # -- Suppressions ------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS suppressions (
            suppression_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_scope ON suppressions(scope, active)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_suppressions_expires ON suppressions(expires_at)")

    conn.commit()
    conn.close()
