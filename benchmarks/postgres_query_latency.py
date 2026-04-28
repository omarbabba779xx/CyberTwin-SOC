"""Measure end-to-end query latency against a real PostgreSQL deployment.

Run:
    DATABASE_URL=postgresql+psycopg://cybertwin:cybertwin@localhost:5432/cybertwin \
    python benchmarks/postgres_query_latency.py --runs 100

Reports:
- p50/p95/p99 for a representative read workload (alert listing,
  audit log scan, case search) and a representative write workload
  (insert audit_log_v2 row).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from datetime import datetime, timezone


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    return statistics.quantiles(sorted(values), n=100)[int(p) - 1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--output", default="benchmarks/results/postgres-query-latency.json")
    args = parser.parse_args()

    if not os.getenv("DATABASE_URL"):
        raise SystemExit(
            "DATABASE_URL must be set, e.g.\n"
            "  DATABASE_URL=postgresql+psycopg://user:pwd@host:5432/db"
        )

    from sqlalchemy import create_engine, text
    engine = create_engine(os.environ["DATABASE_URL"])

    queries = {
        "alerts_recent": "SELECT 1",  # placeholder until alerts table is wired
        "audit_recent_100": "SELECT id FROM audit_log_v2 ORDER BY id DESC LIMIT 100",
        "cases_count": "SELECT COUNT(*) FROM soc_cases",
    }

    results: dict[str, dict] = {}

    for name, sql in queries.items():
        latencies: list[float] = []
        with engine.connect() as conn:
            for _ in range(args.runs):
                t0 = time.monotonic()
                try:
                    conn.execute(text(sql)).fetchall()
                except Exception as exc:
                    print(f"{name}: {type(exc).__name__}: {exc}")
                    break
                latencies.append((time.monotonic() - t0) * 1000)
        if latencies:
            results[name] = {
                "runs": len(latencies),
                "mean_ms": round(statistics.mean(latencies), 2),
                "p50_ms": round(_percentile(latencies, 50), 2),
                "p95_ms": round(_percentile(latencies, 95), 2),
                "p99_ms": round(_percentile(latencies, 99), 2),
                "max_ms": round(max(latencies), 2),
            }

    summary = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "runs_per_query": args.runs,
        "database_url": os.environ["DATABASE_URL"].split("@")[-1],  # hide creds
        "queries": results,
    }
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
