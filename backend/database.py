"""
CyberTwin SOC — SQLite database for simulation history.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybertwin.db"


def _get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = _get_conn()
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
    conn.commit()
    conn.close()


def save_run(scenario_id: str, scenario_name: str, result: dict) -> int:
    """Save a simulation run and return its ID."""
    scores = result.get("scores", {})
    conn = _get_conn()
    cur = conn.execute("""
        INSERT INTO simulation_runs
        (scenario_id, scenario_name, timestamp, total_events, total_alerts, total_incidents,
         overall_score, detection_score, coverage_score, response_score, visibility_score,
         risk_level, maturity_level, full_result)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scenario_id,
        scenario_name,
        datetime.now().isoformat(),
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


def get_runs(limit: int = 50):
    """List recent simulation runs (without full_result)."""
    conn = _get_conn()
    rows = conn.execute("""
        SELECT id, scenario_id, scenario_name, timestamp, total_events, total_alerts,
               total_incidents, overall_score, detection_score, coverage_score,
               response_score, visibility_score, risk_level, maturity_level
        FROM simulation_runs ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_run(run_id: int):
    """Get a full run by ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM simulation_runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    d = dict(row)
    if d.get("full_result"):
        d["full_result"] = json.loads(d["full_result"])
    return d


def get_runs_by_scenario(scenario_id: str):
    conn = _get_conn()
    rows = conn.execute("""
        SELECT id, scenario_id, scenario_name, timestamp, overall_score, detection_score,
               coverage_score, response_score, visibility_score, risk_level
        FROM simulation_runs WHERE scenario_id = ? ORDER BY id DESC
    """, (scenario_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_run(run_id: int):
    conn = _get_conn()
    conn.execute("DELETE FROM simulation_runs WHERE id = ?", (run_id,))
    conn.commit()
    conn.close()


def get_stats():
    conn = _get_conn()
    row = conn.execute("""
        SELECT COUNT(*) as total_runs,
               AVG(overall_score) as avg_score,
               MAX(overall_score) as best_score,
               MIN(overall_score) as worst_score
        FROM simulation_runs
    """).fetchone()
    conn.close()
    return dict(row) if row else {}
