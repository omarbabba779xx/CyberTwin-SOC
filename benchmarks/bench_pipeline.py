"""Quick in-process benchmark of the full simulation pipeline.

Usage:
    python -m benchmarks.bench_pipeline

Writes a JSON file under ``benchmarks/results/``. Designed to run in CI as a
smoke benchmark (a few seconds total) rather than a heavy load-test.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow running from project root via `python benchmarks/bench_pipeline.py`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.orchestrator import SimulationOrchestrator  # noqa: E402

REPEATS = int(os.getenv("BENCH_REPEATS", "3"))
SCENARIO_LIMIT = int(os.getenv("BENCH_SCENARIOS", "3"))


def main() -> int:
    orc = SimulationOrchestrator()
    orc.attack_engine.load_scenarios()
    all_scenarios = orc.attack_engine.list_scenarios()
    scenarios = [s["id"] for s in all_scenarios[:SCENARIO_LIMIT]]
    print(f"Benchmarking {len(scenarios)} scenarios x {REPEATS} runs:")
    for sid in scenarios:
        print(f"  - {sid}")

    results = []
    for sid in scenarios:
        timings = []
        last_report = None
        for _ in range(REPEATS):
            t0 = time.perf_counter()
            last_report = orc.run_simulation(sid)
            timings.append(time.perf_counter() - t0)
        report = last_report or {}
        entry = {
            "scenario": sid,
            "runs": REPEATS,
            "mean_s": round(statistics.mean(timings), 3),
            "min_s": round(min(timings), 3),
            "max_s": round(max(timings), 3),
            "stdev_s": round(statistics.stdev(timings), 3) if len(timings) > 1 else 0.0,
            "total_events": report.get("total_events", 0),
            "total_logs": report.get("total_logs", 0),
            "total_alerts": len(report.get("alerts", []) or []),
            "total_incidents": len(report.get("incidents", []) or []),
        }
        results.append(entry)
        print(
            f"  {sid}: mean={entry['mean_s']}s "
            f"alerts={entry['total_alerts']} "
            f"incidents={entry['total_incidents']} "
            f"logs={entry['total_logs']}"
        )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "repeats_per_scenario": REPEATS,
        "scenarios_tested": len(scenarios),
        "results": results,
    }
    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "latest-pipeline.json"
    out_file.write_text(json.dumps(payload, indent=2))
    print(f"\nSaved to {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
