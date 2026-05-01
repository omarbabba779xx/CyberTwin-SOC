"""Sustained ingestion profiler for CyberTwin SOC.

The profiler exercises the same Normalizer/IngestionPipeline path used by the
API and emits machine-readable JSON for CI, release notes, and capacity runs.
It avoids external services by default; set REDIS_URL to profile Redis Streams.
"""

from __future__ import annotations

import argparse
import json
import sys
import statistics
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.ingestion.pipeline import IngestionPipeline


def _event(i: int) -> dict:
    return {
        "System": {
            "EventID": 4625 if i % 5 == 0 else 4688,
            "Computer": f"WS-{i % 50:03d}",
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
        },
        "EventData": {
            "TargetUserName": f"user{i % 100}",
            "IpAddress": f"10.0.{i % 255}.{(i * 7) % 255}",
            "CommandLine": "powershell -NoProfile -EncodedCommand AAA=" if i % 37 == 0 else "cmd.exe /c whoami",
        },
    }


def run_profile(count: int, batch_size: int, detect: bool, tenant_id: str) -> dict:
    pipeline = IngestionPipeline(buffer_size=max(count + 100, 1000), tenant_id=tenant_id)
    latencies_ms: list[float] = []
    accepted = 0
    rejected = 0

    tracemalloc.start()
    start = time.perf_counter()
    for offset in range(0, count, batch_size):
        batch = [_event(i) for i in range(offset, min(offset + batch_size, count))]
        t0 = time.perf_counter()
        result = pipeline.ingest_batch(batch, source_type="windows_event", tenant_id=tenant_id)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
        accepted += result["accepted"]
        rejected += result["rejected"]
    ingest_seconds = time.perf_counter() - start
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    detection = None
    if detect:
        t0 = time.perf_counter()
        detection = pipeline.detect(tenant_id=tenant_id)
        detection["duration_seconds"] = round(time.perf_counter() - t0, 6)
        detection["alerts"] = len(detection.get("alerts", []))
        detection["incidents"] = len(detection.get("incidents", []))

    throughput = accepted / ingest_seconds if ingest_seconds > 0 else accepted
    p95 = statistics.quantiles(latencies_ms, n=20)[18] if len(latencies_ms) >= 20 else max(latencies_ms or [0.0])
    return {
        "events_requested": count,
        "accepted": accepted,
        "rejected": rejected,
        "batch_size": batch_size,
        "tenant_id": tenant_id,
        "buffer_size": pipeline.buffer_size(tenant_id=tenant_id),
        "ingest_seconds": round(ingest_seconds, 6),
        "events_per_second": round(throughput, 2),
        "batch_latency_ms": {
            "min": round(min(latencies_ms or [0.0]), 3),
            "mean": round(statistics.mean(latencies_ms or [0.0]), 3),
            "p95": round(p95, 3),
            "max": round(max(latencies_ms or [0.0]), 3),
        },
        "memory": {
            "current_mb": round(current_bytes / (1024 * 1024), 3),
            "peak_mb": round(peak_bytes / (1024 * 1024), 3),
        },
        "detection": detection,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile CyberTwin sustained ingestion throughput.")
    parser.add_argument("--events", type=int, default=10000, help="Number of synthetic events to ingest.")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size per ingest call.")
    parser.add_argument("--tenant-id", default="perf-tenant", help="Tenant id for the profiled buffer.")
    parser.add_argument("--detect", action="store_true", help="Run detection after ingestion.")
    args = parser.parse_args()

    if args.events < 1:
        raise SystemExit("--events must be >= 1")
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be >= 1")

    print(json.dumps(run_profile(args.events, args.batch_size, args.detect, args.tenant_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
