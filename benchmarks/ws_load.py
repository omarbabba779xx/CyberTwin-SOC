"""WebSocket load test against the simulation stream.

Spawns N concurrent clients that subscribe to ``/api/simulation/stream``,
record per-message latency, and report p50/p95/p99.

Run:
    python benchmarks/ws_load.py \
        --url ws://localhost:8000/api/simulation/stream \
        --token <JWT> \
        --clients 100 \
        --duration 30
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from typing import Optional

try:
    import websockets
except ImportError:
    raise SystemExit(
        "websockets is required: pip install websockets"
    )


async def _client(url: str, token: Optional[str], duration: float,
                  latencies: list[float], errors: list[str]) -> None:
    headers = []
    if token:
        headers.append(("Authorization", f"Bearer {token}"))

    deadline = time.monotonic() + duration
    try:
        async with websockets.connect(url, additional_headers=headers,
                                       open_timeout=5, close_timeout=2) as ws:
            while time.monotonic() < deadline:
                t0 = time.monotonic()
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                except asyncio.TimeoutError:
                    continue
                latencies.append((time.monotonic() - t0) * 1000)
                # parse to make sure the server is sending valid JSON
                try:
                    json.loads(msg)
                except (TypeError, json.JSONDecodeError):
                    errors.append("non-json")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    return statistics.quantiles(sorted(values), n=100)[int(p) - 1]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--clients", type=int, default=100)
    parser.add_argument("--duration", type=float, default=30.0)
    args = parser.parse_args()

    print(f"Connecting {args.clients} clients to {args.url} for {args.duration}s")
    latencies: list[float] = []
    errors: list[str] = []
    t_start = time.monotonic()
    await asyncio.gather(*(
        _client(args.url, args.token, args.duration, latencies, errors)
        for _ in range(args.clients)
    ))
    elapsed = time.monotonic() - t_start

    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Messages received: {len(latencies)}")
    if latencies:
        print(f"Latency mean: {statistics.mean(latencies):.1f} ms")
        print(f"Latency p50:  {_percentile(latencies, 50):.1f} ms")
        print(f"Latency p95:  {_percentile(latencies, 95):.1f} ms")
        print(f"Latency p99:  {_percentile(latencies, 99):.1f} ms")
    print(f"Errors: {len(errors)}")
    for err in errors[:10]:
        print(f"  {err}")


if __name__ == "__main__":
    asyncio.run(main())
