"""Background job infrastructure (Arq-based).

Provides a task registry with automatic Arq worker enqueue and an
in-process fallback so unit tests and local dev never need a running
worker process.

Usage from a route::

    from backend.jobs import enqueue, get_status

    task_id = await enqueue("simulate_scenario", scenario_id="apt_campaign")
    return {"task_id": task_id}

    # later
    status = get_status(task_id)

To push directly to the Arq worker (skipping fallback)::

    from backend.jobs import enqueue_to_worker

    task_id = await enqueue_to_worker("coverage_recalculate")
    if task_id is None:
        ...  # worker unavailable
"""
from __future__ import annotations

from .registry import (
    enqueue,
    enqueue_to_worker,
    get_status,
    list_registered,
    register_task,
    update_progress,
    TaskStatus,
)
from .config import RedisSettings, queue_settings
from . import tasks as tasks  # noqa: F401 — auto-register all @register_task functions

__all__ = [
    "enqueue",
    "enqueue_to_worker",
    "get_status",
    "list_registered",
    "register_task",
    "update_progress",
    "TaskStatus",
    "RedisSettings",
    "queue_settings",
]
