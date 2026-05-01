"""Smoke tests for the sustained ingestion profiler."""

from __future__ import annotations

import json
import subprocess
import sys


def test_ingestion_profiler_emits_capacity_metrics():
    result = subprocess.run(
        [
            sys.executable,
            "scripts/profile_ingestion.py",
            "--events",
            "200",
            "--batch-size",
            "50",
        ],
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["events_requested"] == 200
    assert body["accepted"] == 200
    assert body["rejected"] == 0
    assert body["events_per_second"] > 0
    assert body["batch_latency_ms"]["p95"] >= 0
    assert body["memory"]["peak_mb"] >= 0
