"""
CyberTwin SOC — Simulation history persistence layer.

When ``DATABASE_URL`` points to PostgreSQL the data goes through the
SQLAlchemy ORM (``backend.db.models.SimulationRun``).  When no
``DATABASE_URL`` is set the module falls back to SQLite for local
development — identical public API either way.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cybertwin.database")

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybertwin.db"

_USE_ORM = bool(os.getenv("DATABASE_URL", ""))


# ---------------------------------------------------------------------------
# ORM implementation (PostgreSQL production path)
# ---------------------------------------------------------------------------

def _orm_init_db() -> None:
    from backend.db.models import Base
    from backend.db.session import engine
    Base.metadata.create_all(bind=engine)
    logger.info("ORM tables ensured (engine=%s)", engine.url)


def _orm_save_run(scenario_id: str, scenario_name: str, result: dict) -> int:
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    scores = result.get("scores", {})
    run_id_str = secrets.token_hex(8)
    run = SimulationRun(
        run_id=run_id_str,
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        tenant_id="default",
        total_events=result.get("total_events", 0),
        total_alerts=len(result.get("alerts", [])),
        total_incidents=len(result.get("incidents", [])),
        overall_score=scores.get("overall_score", 0),
        risk_level=scores.get("risk_level", "unknown"),
        summary_json=result,
    )
    session = SessionLocal()
    try:
        session.add(run)
        session.commit()
        pk = run.id
        return pk
    finally:
        session.close()


def _orm_get_runs(limit: int = 50) -> list[dict]:
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    session = SessionLocal()
    try:
        rows = (
            session.query(SimulationRun)
            .order_by(SimulationRun.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "timestamp": r.started_at.isoformat() if r.started_at else "",
                "total_events": r.total_events,
                "total_alerts": r.total_alerts,
                "total_incidents": r.total_incidents,
                "overall_score": r.overall_score,
                "risk_level": r.risk_level,
            }
            for r in rows
        ]
    finally:
        session.close()


def _orm_get_run(run_id: int) -> Optional[dict]:
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    session = SessionLocal()
    try:
        r = session.query(SimulationRun).filter(SimulationRun.id == run_id).first()
        if r is None:
            return None
        return {
            "id": r.id,
            "scenario_id": r.scenario_id,
            "scenario_name": r.scenario_name,
            "timestamp": r.started_at.isoformat() if r.started_at else "",
            "total_events": r.total_events,
            "total_alerts": r.total_alerts,
            "total_incidents": r.total_incidents,
            "overall_score": r.overall_score,
            "risk_level": r.risk_level,
            "full_result": r.summary_json,
        }
    finally:
        session.close()


def _orm_get_runs_by_scenario(scenario_id: str) -> list[dict]:
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    session = SessionLocal()
    try:
        rows = (
            session.query(SimulationRun)
            .filter(SimulationRun.scenario_id == scenario_id)
            .order_by(SimulationRun.id.desc())
            .all()
        )
        return [
            {
                "id": r.id,
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "timestamp": r.started_at.isoformat() if r.started_at else "",
                "overall_score": r.overall_score,
                "risk_level": r.risk_level,
            }
            for r in rows
        ]
    finally:
        session.close()


def _orm_delete_run(run_id: int) -> None:
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    session = SessionLocal()
    try:
        session.query(SimulationRun).filter(SimulationRun.id == run_id).delete()
        session.commit()
    finally:
        session.close()


def _orm_get_stats() -> dict:
    from sqlalchemy import func as sa_func
    from backend.db.session import SessionLocal
    from backend.db.models import SimulationRun

    session = SessionLocal()
    try:
        row = session.query(
            sa_func.count(SimulationRun.id).label("total_runs"),
            sa_func.avg(SimulationRun.overall_score).label("avg_score"),
            sa_func.max(SimulationRun.overall_score).label("best_score"),
            sa_func.min(SimulationRun.overall_score).label("worst_score"),
        ).first()
        if row is None:
            return {}
        return {
            "total_runs": row.total_runs or 0,
            "avg_score": float(row.avg_score or 0),
            "best_score": float(row.best_score or 0),
            "worst_score": float(row.worst_score or 0),
        }
    finally:
        session.close()


# ---------------------------------------------------------------------------
# SQLite fallback (local development without DATABASE_URL)
# ---------------------------------------------------------------------------

def _sqlite_conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _sqlite_init_db() -> None:
    conn = _sqlite_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS simulation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_id TEXT NOT NULL,
            scenario_name TEXT,
            timestamp TEXT NOT NULL,
            total_events INTEGER DEFAULT 0,
            total_alerts INTEGER DEFAULT 0,
            total_incidents INTEGER DEFAULT 0,
            overall_score REAL DEFAULT 0,
            detection_score REAL DEFAULT 0,
            coverage_score REAL DEFAULT 0,
            response_score REAL DEFAULT 0,
            visibility_score REAL DEFAULT 0,
            risk_level TEXT,
            maturity_level TEXT,
            full_result TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_runs_scenario_id_id "
        "ON simulation_runs (scenario_id, id DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_runs_timestamp "
        "ON simulation_runs (timestamp DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_runs_risk_level "
        "ON simulation_runs (risk_level)"
    )
    conn.commit()
    conn.close()


def _sqlite_save_run(scenario_id: str, scenario_name: str, result: dict) -> int:
    scores = result.get("scores", {})
    conn = _sqlite_conn()
    cur = conn.execute("""
        INSERT INTO simulation_runs
        (scenario_id, scenario_name, timestamp, total_events, total_alerts, total_incidents,
         overall_score, detection_score, coverage_score, response_score, visibility_score,
         risk_level, maturity_level, full_result)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scenario_id, scenario_name,
        datetime.now(timezone.utc).isoformat(),
        result.get("total_events", 0),
        len(result.get("alerts", [])),
        len(result.get("incidents", [])),
        scores.get("overall_score", 0),
        scores.get("detection_score", 0),
        scores.get("coverage_score", 0),
        scores.get("response_score", 0),
        scores.get("visibility_score", 0),
        scores.get("risk_level", ""),
        scores.get("maturity_level", ""),
        json.dumps(result, default=str),
    ))
    conn.commit()
    run_id = cur.lastrowid
    conn.close()
    return run_id


def _sqlite_get_runs(limit: int = 50) -> list[dict]:
    conn = _sqlite_conn()
    rows = conn.execute("""
        SELECT id, scenario_id, scenario_name, timestamp, total_events, total_alerts,
               total_incidents, overall_score, detection_score, coverage_score,
               response_score, visibility_score, risk_level, maturity_level
        FROM simulation_runs ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _sqlite_get_run(run_id: int) -> Optional[dict]:
    conn = _sqlite_conn()
    row = conn.execute("SELECT * FROM simulation_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    if d.get("full_result"):
        d["full_result"] = json.loads(d["full_result"])
    return d


def _sqlite_get_runs_by_scenario(scenario_id: str) -> list[dict]:
    conn = _sqlite_conn()
    rows = conn.execute("""
        SELECT id, scenario_id, scenario_name, timestamp, overall_score, detection_score,
               coverage_score, response_score, visibility_score, risk_level
        FROM simulation_runs WHERE scenario_id = ? ORDER BY id DESC
    """, (scenario_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _sqlite_delete_run(run_id: int) -> None:
    conn = _sqlite_conn()
    conn.execute("DELETE FROM simulation_runs WHERE id = ?", (run_id,))
    conn.commit()
    conn.close()


def _sqlite_get_stats() -> dict:
    conn = _sqlite_conn()
    row = conn.execute("""
        SELECT COUNT(*) as total_runs,
               AVG(overall_score) as avg_score,
               MAX(overall_score) as best_score,
               MIN(overall_score) as worst_score
        FROM simulation_runs
    """).fetchone()
    conn.close()
    return dict(row) if row else {}


# ---------------------------------------------------------------------------
# Public API — delegates to ORM or SQLite depending on DATABASE_URL
# ---------------------------------------------------------------------------

def init_db() -> None:
    if _USE_ORM:
        _orm_init_db()
    else:
        _sqlite_init_db()


def save_run(scenario_id: str, scenario_name: str, result: dict) -> int:
    if _USE_ORM:
        return _orm_save_run(scenario_id, scenario_name, result)
    return _sqlite_save_run(scenario_id, scenario_name, result)


def get_runs(limit: int = 50) -> list[dict]:
    if _USE_ORM:
        return _orm_get_runs(limit)
    return _sqlite_get_runs(limit)


def get_run(run_id: int) -> Optional[dict]:
    if _USE_ORM:
        return _orm_get_run(run_id)
    return _sqlite_get_run(run_id)


def get_runs_by_scenario(scenario_id: str) -> list[dict]:
    if _USE_ORM:
        return _orm_get_runs_by_scenario(scenario_id)
    return _sqlite_get_runs_by_scenario(scenario_id)


def delete_run(run_id: int) -> None:
    if _USE_ORM:
        _orm_delete_run(run_id)
    else:
        _sqlite_delete_run(run_id)


def get_stats() -> dict:
    if _USE_ORM:
        return _orm_get_stats()
    return _sqlite_get_stats()
