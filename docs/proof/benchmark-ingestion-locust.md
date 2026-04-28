# Benchmark — Ingestion Sustained Load (Locust)

**Tool**: [Locust](https://locust.io) — Python-driven load generator
**Script**: [`benchmarks/locust_ingestion.py`](../../benchmarks/locust_ingestion.py)
**Commit**: `0ca70b7`

## Scenario

Each Locust user logs in once, obtains a JWT, then loops over the
ingestion API:

- `POST /api/ingest/event` (single-event ingestion)
- `POST /api/ingest/batch` (batched ingestion, 10 events / call)
- mix of Windows EventLog, syslog, AWS CloudTrail, and Linux auth logs
  (templated by `_windows_event()` etc.)

The goal is to measure **sustained EPS** (events per second) the
backend can ingest **without backpressure** when:
- detection rules run on every event
- correlation engine is active
- audit chain is active
- Redis Streams is the buffer

## Reproduction

```bash
# Login and capture token
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"soc2024"}' | jq -r .access_token)

# Run Locust headless (1k users, 60s, ramp 50 users/sec)
locust -f benchmarks/locust_ingestion.py \
       --host=http://localhost:8000 \
       --users 1000 --spawn-rate 50 --run-time 60s \
       --headless \
       --csv benchmarks/results/locust-1k \
       --html benchmarks/results/locust-1k.html \
       -e CYBERTWIN_TOKEN=$TOKEN
```

The `--csv` flag drops `_stats.csv`, `_stats_history.csv`, and
`_failures.csv` for analysis; `--html` produces a self-contained
report.

## Reference run (local, 1 k users, 2026-04-28)

| Field | Value |
|---|---|
| Commit | `0ca70b7` |
| Host | Windows 10 dev workstation |
| Backend | uvicorn 1 worker, SQLite, Redis local |
| Workers | none (in-process detection) |
| Users | 1 000 |
| Spawn rate | 50 / s |
| Duration | 60 s |

| Metric | Value |
|---|---:|
| Total requests | 41 273 |
| Sustained throughput | **~688 req/s** |
| Sustained EPS (10 events / batch call) | **~3 400 EPS** |
| Failure rate | 0.04 % (transient connection resets at ramp peak) |
| p50 latency (event) | 14 ms |
| p95 latency (event) | 71 ms |
| p99 latency (event) | 198 ms |
| p50 latency (batch) | 38 ms |
| p95 latency (batch) | 142 ms |
| p99 latency (batch) | 401 ms |

> The local single-worker number caps at ~688 req/s purely on uvicorn
> async event-loop saturation. Adding `--workers 4` to uvicorn lifts
> the throughput linearly to ~2 700 req/s in our local checks. The
> production-grade number is on the v3.3 backlog (10k EPS sustained on
> 3-replica Helm deployment).

## Limitations

- Run on a single dev box, ingestion against SQLite. Production
  numbers will differ — Postgres + connection pooling will hit higher
  sustained EPS but with longer p99 latency on first connection.
- Detection rules + correlation are O(events × rules). At 100k+
  events / minute the engine should be moved to the Arq worker
  (already wired) so the API process stays responsive.
- No backpressure tests yet — Locust will happily spam past the
  Redis Streams `maxlen=50000` cap. The buffer trims correctly (see
  `tests/test_ingestion_buffer.py::test_redis_streams_respects_maxlen`)
  but a Locust run that intentionally overflows is on the backlog.

## Files produced (CI artefact)

```
benchmarks/results/locust-1k_stats.csv
benchmarks/results/locust-1k_stats_history.csv
benchmarks/results/locust-1k_failures.csv
benchmarks/results/locust-1k.html
```

## Next steps

- Run the same scenario in a kind cluster with 3 backend replicas + a
  separate Arq worker pod and target **10 000 EPS** sustained.
- Add a CI job that runs Locust at 100 users for 30 s as a smoke test
  (catches throughput regressions early).
