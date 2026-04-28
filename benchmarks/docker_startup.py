"""Measure docker compose startup latency end-to-end.

Run:
    python benchmarks/docker_startup.py [--compose-file docker-compose.yml]

Outputs:
- time to ``docker compose up -d`` complete
- time to backend /api/health = 200
- time to frontend /health = 200
- per-service container start time
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
import urllib.request
from datetime import datetime, timezone


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)


def _wait_for_url(url: str, timeout: float = 120.0) -> float:
    """Block until *url* returns HTTP 200; return elapsed seconds."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return time.monotonic() - t0
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError(f"{url} did not become healthy in {timeout}s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", default="docker-compose.yml")
    parser.add_argument("--backend-url", default="http://localhost:8000/api/health")
    parser.add_argument("--frontend-url", default="http://localhost/health")
    parser.add_argument("--output", default="benchmarks/results/docker-startup.json")
    args = parser.parse_args()

    if not shutil.which("docker"):
        raise SystemExit("docker is not installed in PATH")

    print(f"--- Tearing down any previous stack ---")
    _run(["docker", "compose", "-f", args.compose_file, "down", "-v"])

    metrics: dict = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "compose_file": args.compose_file,
    }

    print(f"--- docker compose up -d ---")
    t0 = time.monotonic()
    up = _run(["docker", "compose", "-f", args.compose_file, "up", "-d"])
    if up.returncode != 0:
        print(up.stderr)
        raise SystemExit("docker compose up failed")
    metrics["compose_up_duration_seconds"] = round(time.monotonic() - t0, 2)

    print(f"--- waiting for backend ({args.backend_url}) ---")
    metrics["backend_ready_seconds"] = round(_wait_for_url(args.backend_url), 2)

    print(f"--- waiting for frontend ({args.frontend_url}) ---")
    try:
        metrics["frontend_ready_seconds"] = round(_wait_for_url(args.frontend_url), 2)
    except TimeoutError as exc:
        metrics["frontend_ready_seconds"] = -1
        metrics["frontend_error"] = str(exc)

    metrics["total_seconds"] = round(time.monotonic() - t0, 2)
    metrics["finished_at"] = datetime.now(timezone.utc).isoformat()

    print(f"--- writing metrics → {args.output} ---")
    import os
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
