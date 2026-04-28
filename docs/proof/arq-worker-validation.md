# Arq Worker — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_arq_jobs.py`](../../tests/test_arq_jobs.py)
**Tests**: 10 / 10 passing
**Module**: `backend/jobs/registry.py`, `backend/jobs/executor.py`

## Scope

Verifies the asynchronous job system that decouples long-running tasks
from HTTP request handlers:

- task registration via `@register_task("name")`
- enqueue → Arq worker → Redis (when reachable)
- in-process fallback when Redis / worker is unreachable (so dev never blocks)
- task lifecycle (queued → running → succeeded / failed)
- progress reporting clamped to [0, 100]
- duplicate registration rejected
- failure capture (error string, traceback)

## Test results

```
$ pytest tests/test_arq_jobs.py -v
tests\test_arq_jobs.py::TestRegistration::test_registered_tasks_listed PASSED
tests\test_arq_jobs.py::TestRegistration::test_duplicate_registration_rejected PASSED
tests\test_arq_jobs.py::TestInProcessExecution::test_enqueue_runs_in_process_and_returns_id PASSED
tests\test_arq_jobs.py::TestInProcessExecution::test_failed_task_recorded_as_failed PASSED
tests\test_arq_jobs.py::TestInProcessExecution::test_unknown_task_raises_keyerror PASSED
tests\test_arq_jobs.py::TestInProcessExecution::test_kwargs_passed_to_task PASSED
tests\test_arq_jobs.py::TestProgress::test_update_progress_clamps_low PASSED
tests\test_arq_jobs.py::TestProgress::test_update_progress_clamps_high PASSED
tests\test_arq_jobs.py::TestStatusEnvelope::test_status_includes_required_fields PASSED
tests\test_arq_jobs.py::TestStatusEnvelope::test_status_for_unknown_id_returns_none PASSED
============= 10 passed in 1.40s =============
```

## Architecture

```
                  ┌────────────────┐
   FastAPI ──────►│  enqueue()     │
                  └────────┬───────┘
                           │
                  Redis    │     no Redis / no worker
                  reachable│              │
                           ▼              ▼
              ┌──────────────────┐   ┌──────────────────┐
              │ Arq pool.enqueue │   │ in-process await  │
              └──────────┬───────┘   └─────────┬────────┘
                         │                     │
                         ▼                     │
                ┌─────────────────┐            │
                │  Arq Worker     │            │
                │  (separate svc) │            │
                └────────┬────────┘            │
                         │                     │
                         ▼                     ▼
              cache.set("cybertwin:task:{id}", {...})
```

## Key assertions

### Successful task transitions through the lifecycle

```python
def test_enqueue_runs_in_process_and_returns_id(self):
    @register_task("test_simple_in_proc")
    async def task(task_id: str, **kw):
        return {"answer": 42}

    task_id = asyncio.run(enqueue("test_simple_in_proc"))

    status = get_status(task_id)
    assert status["status"] == "succeeded"   # PASSES
    assert status["progress"] == 100         # PASSES
    assert status["result"] == {"answer": 42}
```

### Failed task is recorded with traceback

```python
def test_failed_task_recorded_as_failed(self):
    @register_task("test_failing_in_proc")
    async def task(task_id: str, **kw):
        raise RuntimeError("boom")

    task_id = asyncio.run(enqueue("test_failing_in_proc"))
    status = get_status(task_id)
    assert status["status"] == "failed"      # PASSES
    assert "boom" in status["error"]         # PASSES
    assert "RuntimeError" in status["error"] # PASSES
```

### Progress is clamped

```python
update_progress(task_id, -50);   assert progress == 0     # PASSES
update_progress(task_id, 999);   assert progress == 100   # PASSES
```

### Duplicate registration is forbidden

```python
@register_task("name")
async def fn1(...): ...

with pytest.raises(ValueError, match="already registered"):
    @register_task("name")    # PASSES — second registration rejected
    async def fn2(...): ...
```

## Production wiring

| Component | File | Purpose |
|---|---|---|
| Task registry | `backend/jobs/registry.py` | `@register_task` decorator + `enqueue()` API |
| Worker process | `backend/jobs/executor.py` | Arq `WorkerSettings` + dispatcher |
| Redis broker | `backend/jobs/config.py` | `queue_settings()` reads `REDIS_URL` |
| Built-in tasks | `backend/jobs/tasks/*.py` | `coverage_recalculate`, `data_retention` |
| Docker service | `docker-compose.yml::worker` | `python -m backend.jobs.executor` |

## Built-in tasks

| Task name | Purpose | Schedule |
|---|---|---|
| `coverage_recalculate` | Recompute MITRE coverage matrix after rule edits | On demand + nightly |
| `data_retention` | Purge events / audit entries older than `DATA_RETENTION_DAYS` | Daily |

## How to reproduce

### In-process fallback (no Redis required)

```bash
pytest tests/test_arq_jobs.py -v
```

### Full Redis + worker round-trip

```bash
docker compose up -d redis worker
REDIS_URL=redis://localhost:6379 python -c "
import asyncio
from backend.jobs.registry import enqueue, get_status
import time
task_id = asyncio.run(enqueue('coverage_recalculate'))
print('queued:', task_id)
time.sleep(2)
print('status:', get_status(task_id))
"
```

## Limits / next steps

- Job-level idempotency keys are not yet enforced. Re-running the same
  task name with the same args produces a new task_id every time.
- Cron-style scheduling is delegated to Kubernetes CronJobs in the
  Helm chart (`deploy/helm/cybertwin-soc/templates/cronjob.yaml`).
  Native Arq cron support is on the v3.3 backlog.
- Worker auto-scaling (HPA) is documented in the operations runbook
  but the CPU/RAM tuning is operator-specific.
