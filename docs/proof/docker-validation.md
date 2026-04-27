# Docker Compose Validation

> Last manual update: **2026-04-27**.
> Auto-validated on every push by the `Docker Build` job in `ci.yml`.

## What CI validates

The `Docker Build` job in `.github/workflows/ci.yml` runs the following gates,
in order, and **fails the build on any gate**:

```
1.  touch .env                              # stub for local dev parity
2.  docker compose config                   # default stack
3.  docker compose --profile soar config    # SOAR stack
4.  docker compose --profile prod-db config # Postgres stack
5.  docker compose build                    # default
6.  docker compose --profile prod-db build  # prod profile
7.  docker compose up -d                    # default
8.  retry-loop curl http://localhost:8000/api/health    (30 × 5s)
9.  retry-loop curl http://localhost/health             (12 × 5s)
10. docker compose down -v                  # always (cleanup)
```

## Profiles & services validated

| Service        | Default | SOAR profile | prod-db profile | Healthcheck |
|----------------|---------|--------------|-----------------|-------------|
| `redis`        | ✅      | ✅            | ✅              | redis-cli ping |
| `backend`      | ✅      | ✅            | ✅              | `/api/health` |
| `frontend`     | ✅      | ✅            | ✅              | nginx `/health` |
| `postgres`     | —       | —            | ✅              | `pg_isready` |
| `thehive`      | —       | ✅            | —               | TCP probe |
| `cortex`       | —       | ✅            | —               | TCP probe |
| `elasticsearch`| —       | ✅            | —               | cluster yellow |

## Local reproduction

```bash
# Validate every profile
docker compose config
docker compose --profile soar config
docker compose --profile prod-db config

# Build everything you might ship
docker compose build
docker compose --profile prod-db build

# Bring it up + smoke test
touch .env
docker compose up -d

for i in $(seq 1 30); do
  if curl -fsS http://localhost:8000/api/health > /dev/null; then
    echo "Backend OK after ${i} attempt(s)"; break
  fi
  sleep 5
done
curl -fsS http://localhost/health

# Tear down
docker compose down -v
```

## Why the retry loop

The previous incarnation of this job used `sleep 10`, which was unreliable
because:

- `docker compose up -d` returns as soon as containers are *started*, not
  *healthy*.
- Backend warm-up (importing 622 ATT&CK techniques + initialising 46 rules
  + Redis client) takes ~6–9s on a GitHub runner.
- nginx is fast but blocked on `depends_on.backend.condition: service_healthy`,
  so its readiness lags behind the backend.

The retry loop polls `/api/health` and `/health` independently; if either
fails after 30 × 5s and 12 × 5s respectively, container logs from
`backend`, `frontend` and `redis` are dumped automatically (see step
"Dump container logs on failure" in `ci.yml`).

## Hardenings still planned

Per `docs/IMPROVEMENTS.md`:

- **Tier B**: per-service `resources.limits` (memory + CPU) in compose,
  matching what the Helm chart already enforces.
- **Tier B**: `read_only: true` + `tmpfs` for backend after data dir is
  factored out.
- **Tier C**: switch frontend to `nginxinc/nginx-unprivileged` so the K8s
  PSS `runAsNonRoot` policy can be satisfied without port shifting.
