# Docker Compose Validation (v3.2)

> Last manual update: **2026-04-28** (commit `224b757`).
> Auto-validated on every push by the `Docker Build` job in `ci.yml`.
> v3.2 added the `worker` (Arq) service alongside `backend`/`frontend`/`redis`.

## What CI validates

The `Docker Build` job in `.github/workflows/ci.yml` runs the following gates,
in order, and **fails the build on any gate**:

```
1.  create .env with test-only strong secrets
2.  docker compose config                   # default stack
3.  docker compose --profile soar config    # SOAR stack
4.  docker compose build                    # default
5.  docker compose up -d                    # default
6.  retry-loop curl http://localhost:8000/api/health    (30 x 5s)
7.  retry-loop curl http://localhost/health             (12 x 5s)
8.  docker compose down -v                  # always (cleanup)
```

## Profiles & services validated

| Service        | Default | SOAR profile | Healthcheck |
|----------------|---------|--------------|-------------|
| `redis`        | ✅      | ✅            | redis-cli ping |
| `backend`      | ✅      | ✅            | `/api/health` |
| `worker` (Arq) | ✅      | ✅            | container alive (no HTTP) |
| `frontend`     | ✅      | ✅            | nginx `/health` (port 8080, unprivileged) |
| `thehive`      | —       | ✅            | TCP probe |
| `cortex`       | —       | ✅            | TCP probe |
| `elasticsearch`| —       | ✅            | cluster yellow |

## Local reproduction

```bash
# Validate every profile
docker compose config
docker compose --profile soar config

# Build the default stack
docker compose build

# Bring it up + smoke test
cat > .env <<'EOF'
ENV=production
JWT_SECRET=local-compose-secret-for-validation-000000000000
AUTH_ADMIN_PASSWORD=local-admin-password-0000
AUTH_ANALYST_PASSWORD=local-analyst-password-0000
AUTH_VIEWER_PASSWORD=local-viewer-password-0000
EOF
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

## v3.2 hardenings already shipped

- ✅ Frontend now uses `nginxinc/nginx-unprivileged:1.27-alpine` on
  port 8080 (resolves the K8s PSS `runAsNonRoot` blocker).
- ✅ `worker` service runs Arq with the same non-root user as backend
  and shares the Redis broker.
- ✅ docker-compose `restart: unless-stopped` on every long-running service.
- ✅ Quality-gated by Checkov on every push (Dockerfile + secrets +
  Helm framework).

## Hardenings still planned

- **Tier B**: per-service `resources.limits` (memory + CPU) in compose,
  matching what the Helm chart already enforces.
- **Tier B**: `read_only: true` + `tmpfs` for backend after data dir is
  factored out.

## Reproduce the docker-startup benchmark

```bash
python benchmarks/docker_startup.py \
  --backend-url http://localhost:8000/api/health \
  --frontend-url http://localhost:8080/health \
  --output benchmarks/results/docker-startup.json
```

The script measures `compose up`, backend ready, frontend ready and
total wall-clock time. Output is JSON (consumed downstream by Grafana
or Excel).
