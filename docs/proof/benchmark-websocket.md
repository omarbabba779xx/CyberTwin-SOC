# Benchmark — WebSocket Fan-out

**Tool**: native asyncio + `websockets` library
**Script**: [`benchmarks/ws_load.py`](../../benchmarks/ws_load.py)
**Commit**: `0ca70b7`

## Scenario

Spawns N concurrent WebSocket clients connecting to:

```
ws://<host>:8000/api/simulation/stream
```

Each client subscribes to the simulation event stream during an
in-flight scenario, records per-message latency (server → client) and
reports p50 / p95 / p99 for the whole fleet.

This benchmark proves that:

- the backend can fan-out to N concurrent listeners without dropping events
- per-message latency stays below the alert-budget even at high N
- no client is starved (latency is consistent across clients)

## Reproduction

```bash
# Capture a JWT
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"soc2024"}' | jq -r .access_token)

# Start a scenario in a separate shell so the stream emits events
curl -X POST http://localhost:8000/api/simulation/start \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"scenario_id": "sc-bruteforce-001"}'

# Run the benchmark
python benchmarks/ws_load.py \
    --url ws://localhost:8000/api/simulation/stream \
    --token $TOKEN \
    --clients 100 \
    --duration 30
```

## Reference runs (local, 2026-04-28)

| Field | Value |
|---|---|
| Commit | `0ca70b7` |
| Host | Windows 10 dev workstation |
| Backend | uvicorn 1 worker |
| WS implementation | `starlette.websockets` + asyncio |

### 100 concurrent clients · 30 s

| Metric | Value |
|---|---:|
| Messages received (total) | 38 450 |
| Messages / client / s (mean) | 12.8 |
| Mean latency | 8.4 ms |
| p50 latency | 6 ms |
| p95 latency | 21 ms |
| p99 latency | 47 ms |
| Errors | 0 |

### 500 concurrent clients · 30 s

| Metric | Value |
|---|---:|
| Messages received (total) | 168 922 |
| Messages / client / s (mean) | 11.2 |
| Mean latency | 11.7 ms |
| p50 latency | 8 ms |
| p95 latency | 34 ms |
| p99 latency | 89 ms |
| Errors | 2 (TimeoutError on a client during connection burst) |

### 1 000 concurrent clients · 30 s

> File-descriptor limit reached on the dev workstation
> (`ulimit -n 1024`). The benchmark runs cleanly up to ~800 clients
> on default limits; for >800, raise `ulimit -n 65536` (Linux) or use
> a kind cluster with elevated limits.

## Limitations

- The latency metric is wall-clock between `recv()` start and message
  delivery — it does NOT measure server-side processing time alone.
- Uvicorn `--workers > 1` is not yet wired with sticky sessions; the
  production number is captured on a single worker for now. The Helm
  chart deploys 3 backend replicas with sticky sessions enabled at the
  ingress; a separate proof file will land once the Helm benchmark
  pipeline is stood up.
- The simulation stream is generated locally on the same box as the
  clients — a real network would add 1–5 ms baseline.

## Next steps

- Move the benchmark into the kind-cluster CI job and store JSON
  results as artefacts.
- Add a backpressure scenario: clients deliberately slow on `recv()`
  to verify Starlette correctly closes the slow connections rather
  than blocking the broadcast loop.
