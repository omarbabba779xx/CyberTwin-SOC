# Benchmark Results — CyberTwin SOC v3.2

> Last update: **2026-04-28** · Commit: `2a0b2ee` · CI run: 9/9 green
> Reproducer scripts: [`benchmarks/`](../../benchmarks/)
> Live JSON: [`benchmarks/results/`](../../benchmarks/results/)

This page is the **single source of truth** for benchmark headlines.
Every row links to a dedicated proof file with the full reproduction
recipe, raw numbers, EXPLAIN ANALYZE traces, and known limitations.

---

## Headline numbers (v3.2)

| Surface | Tool | Workload | Throughput | p50 | p95 | p99 | Error rate | CPU peak | RAM peak | Detail |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| HTTP API | **k6** | 50 VUs · 90 s · 3 endpoints | — | 4–19 ms | 11–73 ms | 18–121 ms | 0 % | 38 % | 410 MB | [`benchmark-http-k6.md`](benchmark-http-k6.md) |
| Ingestion | **Locust** | 1 000 users · 60 s · single+batch | **3 400 EPS** (batched) | 14 ms | 71 ms | 198 ms | 0.04 % | 71 % | 620 MB | [`benchmark-ingestion-locust.md`](benchmark-ingestion-locust.md) |
| WebSocket fan-out | **`ws_load.py`** | 100 clients · 30 s | 12.8 msg/c/s | 6 ms | 21 ms | 47 ms | 0 % | 41 % | 480 MB | [`benchmark-websocket.md`](benchmark-websocket.md) |
| WebSocket fan-out | **`ws_load.py`** | 500 clients · 30 s | 11.2 msg/c/s | 8 ms | 34 ms | 89 ms | 0.001 % | 64 % | 510 MB | [`benchmark-websocket.md`](benchmark-websocket.md) |
| PostgreSQL read | **`postgres_query_latency.py`** | 200 runs / query · 3 queries · pg16 | — | 0.18–0.84 ms | 0.32–1.74 ms | 0.61–3.42 ms | 0 % | 18 % | 220 MB | [`benchmark-postgres.md`](benchmark-postgres.md) |
| Docker compose cold | **`docker_startup.py`** | full stack (backend, frontend, redis, worker) | — | — | — | — | — | 89 % | 1.4 GB | [`benchmark-docker-startup.md`](benchmark-docker-startup.md) |
| Frontend Lighthouse | **Lighthouse CI** | local `dist/` served | Perf 0.82 / a11y 0.95 / BP 0.96 / SEO 0.91 | LCP 2.1 s | TBT 122 ms | CLS 0.04 | — | — | — | [`frontend-lighthouse-report.md`](frontend-lighthouse-report.md) |

> **CPU peak / RAM peak** are measured on the Windows 10 dev workstation
> (8 logical cores, 32 GB RAM) during the steady-state phase. Production
> envelope on a 3-replica Helm deployment is on the v3.3 backlog.

### Cold-start envelope (Docker compose)

| Step | Duration |
|---|---:|
| `docker compose up -d` returns | 8.4 s |
| Backend `/api/health` 200 | 11.2 s |
| Frontend `/health` 200 | 12.7 s |
| **Total cold start** | **12.7 s** |
| Warm cache rerun | 6–8 s |

---

## Reference environment (all runs above)

| Field | Value |
|---|---|
| Commit | `2a0b2ee` (this push) — benchmarks were captured at `0ca70b7` |
| Host | Windows 10 dev workstation |
| CPU | x86_64 · 8 logical cores |
| RAM | 32 GB |
| Backend | uvicorn 1 worker (single-process, deliberate baseline) |
| Cache | Redis 7 (Docker) |
| DB | SQLite by default; PostgreSQL 16 for the `benchmark-postgres` row |
| Python | 3.12.10 |
| Node | 20.x |
| Docker | Desktop 4.34, WSL2 backend, compose plugin v2.27 |

---

## Supporting in-process pipeline benchmark

The end-to-end **simulator pipeline** (attack engine → telemetry →
detection → correlation → scoring → AI report) runs entirely in-process
and is the deterministic safety net for refactors. It is **not**
representative of production HTTP throughput; for that, see the k6 and
Locust rows above.

| Scenario | Mean | Min | Max | Stdev | Events | Logs | Alerts | Incidents |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `sc-apt-campaign-001` | 4.652 s | 4.412 s | 4.793 s | 0.209 s | 68 | 68 | 8 | 1 |
| `sc-bruteforce-001`   | 12.597 s | 12.217 s | 12.927 s | 0.357 s | 4 581 | 4 581 | 12 | 1 |
| `sc-cloud-attack-001` | 4.409 s | 4.405 s | 4.415 s | 0.005 s | 82 | 82 | 6 | 1 |

Reproduce: `python -m benchmarks.bench_pipeline`
Output: `benchmarks/results/latest-pipeline.json`

---

## Reproduction (one command per surface)

```bash
# 1. HTTP API load (k6)
k6 run benchmarks/k6_api.js -e BASE_URL=http://localhost:8000 -e CYBERTWIN_TOKEN=$TOKEN

# 2. Sustained ingestion (Locust)
locust -f benchmarks/locust_ingestion.py --host=http://localhost:8000 \
       --users 1000 --spawn-rate 50 --run-time 60s --headless \
       --csv benchmarks/results/locust-1k --html benchmarks/results/locust-1k.html

# 3. WebSocket fan-out
python benchmarks/ws_load.py --url ws://localhost:8000/api/simulation/stream \
       --token $TOKEN --clients 100 --duration 30

# 4. Docker compose cold start
python benchmarks/docker_startup.py --compose-file docker-compose.yml

# 5. PostgreSQL query latency (pg16 already running)
python benchmarks/postgres_query_latency.py --runs 200 \
       --output benchmarks/results/postgres-query-latency.json

# 6. Frontend Lighthouse
cd frontend && npm install --no-save @lhci/cli@0.14.x && npx lhci autorun

# 7. End-to-end simulator pipeline (deterministic, no Docker)
python -m benchmarks.bench_pipeline
```

---

## Caveats — production envelope vs. local envelope

The numbers above are **single-host, single-worker** measurements
captured on a dev workstation. They prove the pipeline runs end-to-end
and the regression-detection thresholds are wired. Production
envelope work (3-replica Helm deployment, sticky-session ingress,
PgBouncer, Redis cluster) is on the v3.3 roadmap and will land in:

- `benchmark-helm-cluster.md` — k6 + Locust against a kind cluster
- `benchmark-redis-streams-cluster.md` — Redis Streams maxlen + trim
- `benchmark-arq-worker.md` — Arq queue depth at sustained EPS

When those land, the "Headline numbers" table will gain a second
column per row labelled **"Production"**.
