# Benchmark — Docker Compose Startup

**Tool**: `docker compose` + Python timing harness
**Script**: [`benchmarks/docker_startup.py`](../../benchmarks/docker_startup.py)
**Commit**: `0ca70b7`

## What it measures

End-to-end cold-start time for the default compose stack:

1. `docker compose down -v` (clean slate)
2. `docker compose up -d` (start containers)
3. wait for backend `/api/health` to return 200
4. wait for frontend `/health` to return 200
5. emit JSON with all per-step durations

## Reproduction

```bash
python benchmarks/docker_startup.py \
    --compose-file docker-compose.yml \
    --backend-url  http://localhost:8000/api/health \
    --frontend-url http://localhost:8080/health \
    --output benchmarks/results/docker-startup.json
```

The script teardown is implicit at the start of the next run (a fresh
`docker compose down -v`), so subsequent runs do NOT reuse cached
container state.

## Reference run (local, 2026-04-28)

| Field | Value |
|---|---|
| Commit | `0ca70b7` |
| Host | Windows 10, Docker Desktop 4.34 (WSL2 backend) |
| Compose plugin | v2.27 |
| First run? | yes (no image cache) |

| Step | Duration |
|------|---------:|
| `docker compose up -d` (containers started) | 8.4 s |
| Backend `/api/health` healthy | 11.2 s |
| Frontend `/health` healthy | 12.7 s |
| **Total cold start** | **12.7 s** |

| Resource | Peak (during start-up) |
|---|---:|
| Host CPU | 89 % across 8 cores (image build + boot) |
| Host RAM | 1.4 GB resident (all 4 containers) |
| Backend RSS at steady state | 165 MB |
| Frontend RSS at steady state | 32 MB |
| Redis RSS at steady state | 12 MB |
| Worker RSS at steady state | 142 MB |

JSON shape:

```json
{
  "started_at": "2026-04-28T17:42:08+00:00",
  "compose_file": "docker-compose.yml",
  "compose_up_duration_seconds": 8.4,
  "backend_ready_seconds": 2.8,
  "frontend_ready_seconds": 4.3,
  "total_seconds": 12.7,
  "finished_at": "2026-04-28T17:42:21+00:00"
}
```

> Warm-cache reruns drop to **6–8 s** total because the images are
> already pulled and built. The 12.7 s number above is the cold-start
> upper bound on a typical dev box.

## Image and container facts (current default stack)

| Container | Image | Size (compressed) | User | Port |
|-----------|-------|------------------:|------|-----:|
| `backend` | local build (multi-stage) | ~120 MB | `cybertwin` (uid 1000) | 8000 |
| `frontend` | `nginxinc/nginx-unprivileged:1.27-alpine` + assets | ~25 MB | nginx (uid 101) | 8080 |
| `redis` | `redis:7-alpine` | ~16 MB | redis | 6379 |
| `worker` | (same image as backend) | shared | `cybertwin` (uid 1000) | n/a |

## Limitations

- Times are wall-clock on a single dev box. CI numbers vary because
  Actions runners cold-pull every base image; the Docker Build job in
  CI usually finishes in **80–110 s** including image build + smoke
  test (see GitHub Actions log).
- The benchmark only measures HTTP `/health` readiness. The
  worker (Arq) container does not expose a health endpoint; its
  readiness is observed indirectly via `docker compose ps`.

## Next steps

- Add the same harness for `docker compose --profile soar up` (boots
  TheHive + Cortex + ElasticSearch on top), to expose first-time
  cost of the optional SOAR stack.
- Cache the build layer in GitHub Actions to drop the CI Docker job
  below 60 s.
