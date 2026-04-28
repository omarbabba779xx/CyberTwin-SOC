# Benchmark — HTTP API Load (k6)

**Tool**: [Grafana k6](https://k6.io) — synthetic HTTP load
**Script**: [`benchmarks/k6_api.js`](../../benchmarks/k6_api.js)
**Commit**: `0ca70b7`

## Scenario

Three-stage load profile against a running CyberTwin backend:

| Stage    | VUs (virtual users) | Duration | Purpose |
|----------|--------------------:|---------:|---------|
| Ramp-up  | 0 → 25              | 15 s     | warm caches, fill connection pool |
| Steady   | 25 → 50             | 60 s     | sustained load measurement |
| Ramp-dn  | 50 → 0              | 15 s     | drain |

Each VU loops over three endpoints:
1. `GET /api/health` (no auth, fast)
2. `GET /api/auth/me` (auth, light)
3. `GET /api/alerts?limit=20` (auth, DB read)

## Thresholds (configured in script)

| Metric | Threshold | Effect |
|---|---|---|
| `http_req_duration` p95 | < 500 ms | k6 exit non-zero on breach |
| `http_req_failed` rate  | < 1 %    | k6 exit non-zero on breach |
| `http_errors` count     | < 10     | k6 exit non-zero on breach |

## Reproduction

```bash
# Backend running locally on :8000
export CYBERTWIN_TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"soc2024"}' | jq -r .access_token)

k6 run -e BASE_URL=http://localhost:8000 \
       -e CYBERTWIN_TOKEN=$CYBERTWIN_TOKEN \
       --summary-export=benchmarks/results/k6-summary.json \
       benchmarks/k6_api.js
```

## Reference run (local, 2026-04-28)

| Field | Value |
|---|---|
| Commit | `0ca70b7` |
| Host | Windows 10 dev workstation |
| CPU | x86_64, 8 logical cores |
| RAM | 32 GB |
| Backend mode | uvicorn (single worker), no Docker |
| Database | SQLite |
| Cache | Redis local (Docker) |

| Endpoint | p50 (ms) | p95 (ms) | p99 (ms) | error rate |
|---|---:|---:|---:|---:|
| `GET /api/health` | 4 | 11 | 18 | 0 % |
| `GET /api/auth/me` | 8 | 26 | 41 | 0 % |
| `GET /api/alerts?limit=20` | 19 | 73 | 121 | 0 % |

> Numbers are from a single dev workstation and are upper bounds, not
> production figures. They demonstrate that the script runs end-to-end
> and the thresholds catch regressions. Production benchmarks (multi-
> worker uvicorn behind nginx, PostgreSQL, Redis cluster) are tracked
> separately under `benchmarks/results/k6-prod-*.json`.

## Limitations

- Single dev box, single uvicorn worker — does NOT represent a
  production fleet behind a load balancer.
- WebSocket fan-out is NOT exercised by k6 — see
  [`benchmark-websocket.md`](benchmark-websocket.md).
- The `alerts` endpoint queries SQLite in this run; production uses
  PostgreSQL with composite indexes (see [`benchmark-postgres.md`](benchmark-postgres.md)).

## Next steps

- Run k6 against a 3-replica `helm install` on a kind cluster, store
  the JSON summary as a CI artefact.
- Add a workflow scenario that drives the full case lifecycle
  (login → ingest → simulate → ack alert → close case).
