"""Arq worker process for CyberTwin background jobs.

Run standalone:
    python -m backend.jobs.executor

Or via Docker:
    docker-compose up worker

The worker picks tasks off the Redis queue and delegates to the same
async functions registered via ``@register_task``.  Status / progress
writes go through the cache layer so the API can poll without any direct
coupling to the worker process.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

from arq import func, run_worker
from arq.connections import RedisSettings as ArqRedisSettings

from backend.jobs.config import QUEUE_NAME, DEFAULT_TIMEOUT, DEFAULT_RETRIES, queue_settings
from backend.jobs.registry import (
    _TASKS,
    TaskStatus,
    _now_iso,
    _write,
    update_progress,
)

import backend.jobs.tasks  # noqa: F401 — force registration of @register_task functions

logger = logging.getLogger("cybertwin.worker")


def _arq_redis_settings() -> ArqRedisSettings:
    cfg = queue_settings()
    return ArqRedisSettings(
        host=cfg.host,
        port=cfg.port,
        database=cfg.database,
        password=cfg.password,
    )


async def _run_task(ctx: dict[str, Any], task_name: str, **kwargs: Any) -> Any:
    """Generic dispatcher invoked by Arq for every enqueued job.

    ``task_name`` maps to a function in the task registry.  Extra kwargs
    are forwarded verbatim.  The ``task_id`` is stored by the caller in
    ``kwargs`` before enqueue.
    """
    task_id: str = kwargs.pop("task_id")
    fn = _TASKS.get(task_name)
    if fn is None:
        msg = f"Unknown task '{task_name}' — registered: {list(_TASKS)}"
        logger.error(msg)
        _write(
            task_id,
            status=TaskStatus.FAILED.value,
            error=msg,
            finished_at=_now_iso(),
        )
        raise KeyError(msg)

    _write(task_id, status=TaskStatus.RUNNING.value, started_at=_now_iso())
    logger.info("task=%s id=%s — started", task_name, task_id)

    try:
        result = await fn(task_id=task_id, **kwargs)
        _write(
            task_id,
            status=TaskStatus.SUCCEEDED.value,
            progress=100,
            result=result,
            finished_at=_now_iso(),
        )
        logger.info("task=%s id=%s — succeeded", task_name, task_id)
        return result
    except Exception:
        import traceback

        tb = traceback.format_exc()[-2000:]
        _write(
            task_id,
            status=TaskStatus.FAILED.value,
            error=f"{sys.exc_info()[0].__name__}: {sys.exc_info()[1]}",
            traceback=tb,
            finished_at=_now_iso(),
        )
        logger.exception("task=%s id=%s — failed", task_name, task_id)
        raise


async def on_startup(ctx: dict[str, Any]) -> None:
    logger.info(
        "Worker starting — registered tasks: %s", sorted(_TASKS.keys())
    )


async def on_shutdown(ctx: dict[str, Any]) -> None:
    logger.info("Worker shutting down")


class WorkerSettings:
    """Arq discovers this class by convention when the module is passed
    as ``--class`` or via ``run_worker``."""

    functions = [func(_run_task, name="run_task")]
    redis_settings = _arq_redis_settings()
    queue_name = QUEUE_NAME
    max_jobs = 10
    job_timeout = DEFAULT_TIMEOUT
    max_tries = DEFAULT_RETRIES + 1  # arq counts the initial attempt
    on_startup = on_startup
    on_shutdown = on_shutdown
    allow_abort_jobs = True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    run_worker(WorkerSettings)  # type: ignore[arg-type]
