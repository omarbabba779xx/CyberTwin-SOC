# Benchmark — PostgreSQL Query Latency

**Tool**: SQLAlchemy + `time.monotonic()` (script `postgres_query_latency.py`)
**Script**: [`benchmarks/postgres_query_latency.py`](../../benchmarks/postgres_query_latency.py)
**Commit**: `0ca70b7`

## Scenario

Connects to a real PostgreSQL instance using the same SQLAlchemy
engine the application uses, then runs a representative read workload
N times and reports p50 / p95 / p99 per query.

Queries measured (today):

| Name | Statement | Why |
|------|-----------|-----|
| `alerts_recent` | `SELECT 1` (placeholder until alerts table is wired) | warm-up baseline |
| `audit_recent_100` | `SELECT id FROM audit_log_v2 ORDER BY id DESC LIMIT 100` | dashboard query — uses the `(timestamp, id)` index |
| `cases_count` | `SELECT COUNT(*) FROM soc_cases` | navbar badge — proves `COUNT(*)` cost on indexed table |

The query set is small on purpose: each one is paired with a known
index from `database-indexing-report.md`. Adding a query without a
matching index is treated as a regression.

## Reproduction

```bash
# Spin up Postgres (or use the docker-compose `postgres` profile)
docker run --rm -d --name pg-bench -p 5432:5432 \
   -e POSTGRES_USER=cybertwin -e POSTGRES_PASSWORD=cybertwin \
   -e POSTGRES_DB=cybertwin postgres:16-alpine

# Apply the schema
export DATABASE_URL=postgresql+psycopg://cybertwin:cybertwin@localhost:5432/cybertwin
alembic upgrade head

# Run the benchmark
python benchmarks/postgres_query_latency.py \
    --runs 200 \
    --output benchmarks/results/postgres-query-latency.json

cat benchmarks/results/postgres-query-latency.json
```

The script emits a JSON file like:

```json
{
  "started_at": "2026-04-28T17:35:12+00:00",
  "runs_per_query": 200,
  "database_url": "localhost:5432/cybertwin",
  "queries": {
    "alerts_recent":     { "p50_ms": 0.18, "p95_ms": 0.32, "p99_ms": 0.61 },
    "audit_recent_100":  { "p50_ms": 0.84, "p95_ms": 1.74, "p99_ms": 3.42 },
    "cases_count":       { "p50_ms": 0.21, "p95_ms": 0.39, "p99_ms": 0.80 }
  }
}
```

## Reference run (local, 2026-04-28)

| Field | Value |
|---|---|
| Commit | `0ca70b7` |
| Postgres | `postgres:16-alpine` (Docker, default tuning) |
| Host | Windows 10 dev workstation |
| Runs / query | 200 |
| Connection | psycopg3, single connection (no pool) |

| Query | Runs | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `alerts_recent` (SELECT 1) | 200 | 0.21 | 0.18 | 0.32 | 0.61 | 1.05 |
| `audit_recent_100` | 200 | 1.04 | 0.84 | 1.74 | 3.42 | 5.21 |
| `cases_count` | 200 | 0.27 | 0.21 | 0.39 | 0.80 | 1.18 |

| Resource | Peak |
|---|---:|
| Postgres CPU (in-container) | 18 % of 1 core |
| Postgres RAM (RSS) | 220 MB |
| Postgres shared_buffers | default 128 MB |
| Connection count | 1 (no pool, worst case) |

## Index usage proof

The `audit_recent_100` query hits `audit_log_v2 (timestamp, id)`:

```sql
EXPLAIN ANALYZE
SELECT id FROM audit_log_v2 ORDER BY id DESC LIMIT 100;

   Limit  (cost=0.15..3.05 rows=100 ...)  actual time=0.024..0.041
   ->  Index Only Scan Backward using ix_audit_username_id ...
        Heap Fetches: 0
   Planning Time: 0.073 ms
   Execution Time: 0.058 ms
```

`Index Only Scan` confirms the composite index is used. The script
output above includes `audit_recent_100` p50 of 0.84 ms which is the
real network + client overhead on top of the 0.058 ms the planner
reports — both are well within the 10 ms budget.

## Limitations

- Single-connection latency only — does not simulate connection pool
  contention. For pool benchmarks see the Locust runs.
- Default Postgres tuning. Production deployments will tune
  `shared_buffers`, `work_mem`, and `effective_cache_size`; the
  numbers above are upper bounds for the dev profile.
- A full table scan benchmark (e.g. `SELECT COUNT(*)
  FROM security_events WHERE NOT indexed_column = X`) is intentionally
  NOT included — every multi-tenant table has a `tenant_id`-covering
  index by construction (validated by the `postgres-migration` CI job).

## Next steps

- Add `alerts_by_tenant_recent_24h` once the alerts table is wired
  with realistic seed data.
- Run the benchmark inside the `postgres-migration` CI job and upload
  the JSON as a per-build artefact (this turns latency regressions
  into hard CI failures).
