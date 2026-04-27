"""Database index audit tool.

Inspects the SQLite database used by CyberTwin SOC and verifies that
every table has the indexes the code-base depends on for its dominant
access patterns. Prints a Markdown report and exits 1 on any missing
index so the script can be wired into CI as a regression gate.

Usage:
    python -m scripts.check_db_indexes                      # report + exit code
    python -m scripts.check_db_indexes --report PATH        # write Markdown
    python -m scripts.check_db_indexes --json               # JSON output

Drop-in for ``pytest``:
    pytest scripts/test_db_indexes.py
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "cybertwin.db"


# Required indexes per table. Each entry maps a table name to a dict of
# {logical_name: required_columns}. The check passes if at least one
# index on that table covers every required column in the listed order.
EXPECTED_INDEXES: dict[str, dict[str, list[str]]] = {
    "simulation_runs": {
        "scenario_id_filter": ["scenario_id"],   # composite (scenario_id, id) is fine
        "timestamp_window":   ["timestamp"],
        "risk_level_filter":  ["risk_level"],
    },
    "audit_log": {
        "timestamp_window":  ["timestamp"],
        "username_filter":   ["username"],
        "action_filter":     ["action"],
        "status_filter":     ["status"],
    },
    "alert_feedback": {
        "rule_id_filter":  ["rule_id"],
        "alert_id_filter": ["alert_id"],
    },
    "soc_cases": {
        "status_filter":   ["status"],
        "severity_filter": ["severity"],
        "assignee_filter": ["assignee"],
    },
    "case_comments": {
        "case_id_filter": ["case_id"],
    },
    "case_evidence": {
        "case_id_filter": ["case_id"],
    },
    "suppressions": {
        "scope_active_filter": ["scope"],     # part of composite (scope, active)
        "expires_at_filter":   ["expires_at"],
    },
}


def _conn() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Database not found at {DB_PATH}. "
            "Boot the API once (or run init scripts) to materialise it."
        )
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    ).fetchall()
    return [r["name"] for r in rows]


def list_indexes(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    """Return a list of {name, columns, unique, partial} for every index on ``table``."""
    indexes = []
    for row in conn.execute(f"PRAGMA index_list('{table}')").fetchall():
        cols = [
            r["name"]
            for r in conn.execute(f"PRAGMA index_info('{row['name']}')").fetchall()
        ]
        indexes.append({
            "name": row["name"],
            "unique": bool(row["unique"]),
            "partial": bool(row["partial"]) if "partial" in row.keys() else False,
            "columns": cols,
        })
    return indexes


def covers(index_columns: list[str], required: list[str]) -> bool:
    """An index covers a requirement if its leading columns match exactly."""
    return index_columns[: len(required)] == required


def audit() -> tuple[dict[str, dict[str, Any]], int]:
    conn = _conn()
    try:
        tables = set(list_tables(conn))
        report: dict[str, dict[str, Any]] = {}
        missing_total = 0

        for table, expected in EXPECTED_INDEXES.items():
            entry: dict[str, Any] = {
                "exists": table in tables,
                "indexes": [],
                "expected": {},
                "missing": [],
            }
            if not entry["exists"]:
                entry["missing"] = list(expected.keys())
                missing_total += len(expected)
                report[table] = entry
                continue
            entry["indexes"] = list_indexes(conn, table)
            for name, required_cols in expected.items():
                ok = any(
                    covers(idx["columns"], required_cols)
                    for idx in entry["indexes"]
                )
                entry["expected"][name] = {
                    "required": required_cols,
                    "satisfied": ok,
                }
                if not ok:
                    entry["missing"].append(name)
                    missing_total += 1
            report[table] = entry

        return report, missing_total
    finally:
        conn.close()


def render_markdown(report: dict[str, dict[str, Any]], missing_total: int) -> str:
    lines = ["# Database Index Audit", ""]
    lines.append(f"- Database: `{DB_PATH}`")
    lines.append(f"- Tables checked: **{len(report)}**")
    lines.append(f"- Missing indexes: **{missing_total}**")
    lines.append("")

    for table, entry in report.items():
        lines.append(f"## `{table}`")
        if not entry["exists"]:
            lines.append(f"> ❌ Table not found. Expected indexes: "
                         f"{', '.join(entry['missing']) or '(none)'}")
            lines.append("")
            continue
        lines.append("")
        lines.append("**Existing indexes**")
        if not entry["indexes"]:
            lines.append("- *(none)*")
        else:
            for idx in entry["indexes"]:
                flags = []
                if idx["unique"]:
                    flags.append("UNIQUE")
                if idx["partial"]:
                    flags.append("PARTIAL")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                lines.append(f"- `{idx['name']}` on ({', '.join(idx['columns'])}){flag_str}")
        lines.append("")
        lines.append("**Expected coverage**")
        for name, info in entry["expected"].items():
            tick = "✅" if info["satisfied"] else "❌"
            lines.append(f"- {tick} `{name}` → ({', '.join(info['required'])})")
        lines.append("")

    if missing_total:
        lines.append("## Result: ❌ FAIL")
        lines.append(f"{missing_total} required index(es) missing.")
    else:
        lines.append("## Result: ✅ PASS")
        lines.append("Every required index is present.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    ap.add_argument("--report", type=Path, default=None,
                    help="Write Markdown report to this path (e.g. docs/proof/database-indexing-report.md)")
    args = ap.parse_args()

    report, missing = audit()

    if args.json:
        print(json.dumps({"missing_total": missing, "tables": report},
                          indent=2, default=str))
    else:
        md = render_markdown(report, missing)
        print(md)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(md, encoding="utf-8")
            print(f"\n[wrote {args.report}]", file=sys.stderr)

    return 0 if missing == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
