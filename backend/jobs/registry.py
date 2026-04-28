"""Task registry with Arq worker enqueue and in-process fallback.

The API process can push jobs to a Redis-backed Arq worker when one is
available. If the worker (or Redis) is unreachable the task runs
in-process so development and testing never require a running worker.

Status keys live under ``cybertwin:task:{task_id}`` with these fields:
- status   -> queued | running | succeeded | failed | cancelled
- result   -> JSON-encoded payload or null
- error    -> error string or null
- progress -> 0..100 integer
- enqueued_at, started_at, finished_at -> ISO-8601 UTC
"""
from __future__ import annotations

import json
import logging
import secrets
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from backend.cache import cache

logger = logging.getLogger("cybertwin.jobs")

_TASKS: dict[str, Callable[..., Awaitable[Any]]] = {}

# Lazily initialised Arq connection pool (one per process).
_arq_pool: Any | None = None
_arq_pool_failed: bool = False


class TaskStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _key(task_id: str) -> str:
    return f"cybertwin:task:{task_id}"


def _write(task_id: str, **fields: Any) -> None:
    existing = get_status(task_id) or {}
    existing.update(fields)
    cache.set(_key(task_id), json.dumps(existing, default=str), ttl=86400)


def register_task(name: str):
    """Decorator: registers an async function as an enqueueable task."""
    def _wrap(fn: Callable[..., Awaitable[Any]]):
        if name in _TASKS:
            raise ValueError(f"Task '{name}' already registered")
        _TASKS[name] = fn
        return fn
    return _wrap


# ---------------------------------------------------------------------------
# Arq worker enqueue
# ---------------------------------------------------------------------------

async def _get_arq_pool() -> Any:
    """Return (and cache) an ``ArqRedis`` connection pool, or *None*.

    After a connection failure, further attempts are skipped for the
    lifetime of the process to avoid slow retries (e.g. in tests).
    Call ``reset_arq_pool()`` to re-enable.
    """
    global _arq_pool, _arq_pool_failed  # noqa: PLW0603
    if _arq_pool is not None:
        return _arq_pool
    if _arq_pool_failed:
        return None
    try:
        import asyncio

        from arq import create_pool
        from arq.connections import RedisSettings as ArqRedisSettings

        from backend.jobs.config import queue_settings

        cfg = queue_settings()
        _arq_pool = await asyncio.wait_for(
            create_pool(
                ArqRedisSettings(
                    host=cfg.host,
                    port=cfg.port,
                    database=cfg.database,
                    password=cfg.password,
                    conn_timeout=2,
                ),
            ),
            timeout=3,
        )
        return _arq_pool
    except Exception:
        _arq_pool_failed = True
        logger.debug("Arq pool unavailable — will use in-process fallback", exc_info=True)
        return None


def reset_arq_pool() -> None:
    """Reset the cached pool so the next ``enqueue()`` retries the connection."""
    global _arq_pool, _arq_pool_failed  # noqa: PLW0603
    _arq_pool = None
    _arq_pool_failed = False


async def enqueue_to_worker(task_name: str, **kwargs: Any) -> str | None:
    """Push a job to the Arq worker via Redis.

    Returns the ``task_id`` on success or *None* when the worker / Redis
    is unreachable.
    """
    pool = await _get_arq_pool()
    if pool is None:
        return None

    from backend.jobs.config import QUEUE_NAME

    task_id = secrets.token_hex(8)
    _write(
        task_id,
        task=task_name,
        status=TaskStatus.QUEUED.value,
        progress=0,
        result=None,
        error=None,
        enqueued_at=_now_iso(),
    )

    try:
        await pool.enqueue_job(
            "run_task",
            task_name,
            task_id=task_id,
            _queue_name=QUEUE_NAME,
            **kwargs,
        )
        logger.info("Enqueued task=%s id=%s via Arq worker", task_name, task_id)
        return task_id
    except Exception:
        logger.warning(
            "Failed to enqueue task=%s via Arq — falling back to in-process",
            task_name,
            exc_info=True,
        )
        reset_arq_pool()
        return None


# ---------------------------------------------------------------------------
# In-process fallback executor
# ---------------------------------------------------------------------------

async def _run_in_process(task_name: str, **kwargs: Any) -> str:
    """Execute the task synchronously inside the API process."""
    if task_name not in _TASKS:
        raise KeyError(f"Unknown task '{task_name}'. Registered: {list(_TASKS)}")

    task_id = secrets.token_hex(8)
    _write(
        task_id,
        task=task_name,
        status=TaskStatus.QUEUED.value,
        progress=0,
        result=None,
        error=None,
        enqueued_at=_now_iso(),
    )

    fn = _TASKS[task_name]
    _write(task_id, status=TaskStatus.RUNNING.value, started_at=_now_iso())
    try:
        result = await fn(task_id=task_id, **kwargs)
        _write(
            task_id,
            status=TaskStatus.SUCCEEDED.value,
            progress=100,
            result=result,
            finished_at=_now_iso(),
        )
    except Exception as exc:  # noqa: BLE001
        _write(
            task_id,
            status=TaskStatus.FAILED.value,
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc()[-2000:],
            finished_at=_now_iso(),
        )
    return task_id


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enqueue(task_name: str, **kwargs: Any) -> str:
    """Enqueue a task. Returns the task_id immediately.

    Tries the Arq worker first; if unavailable, falls back to running the
    task in-process so the call always succeeds.
    """
    if task_name not in _TASKS:
        raise KeyError(f"Unknown task '{task_name}'. Registered: {list(_TASKS)}")

    worker_id = await enqueue_to_worker(task_name, **kwargs)
    if worker_id is not None:
        return worker_id

    logger.debug("Running task=%s in-process (no Arq worker)", task_name)
    return await _run_in_process(task_name, **kwargs)


def get_status(task_id: str) -> dict[str, Any] | None:
    raw = cache.get(_key(task_id))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def update_progress(task_id: str, percent: int) -> None:
    """Tasks call this to report progress (clamped to 0..100)."""
    _write(task_id, progress=max(0, min(100, int(percent))))


def list_registered() -> list[str]:
    return sorted(_TASKS)
