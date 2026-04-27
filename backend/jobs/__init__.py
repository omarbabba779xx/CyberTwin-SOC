"""Background job infrastructure (Arq-based).

Today this module exposes a thin scaffold: a Redis broker, a task registry,
and an in-memory fallback so unit tests never need a worker process. Future
phases will migrate `simulation:run`, `report:export` and `soar:push` from
in-request execution to async tasks (see docs/IMPROVEMENTS.md).

Usage from a route:

    from backend.jobs import enqueue, get_status

    task_id = await enqueue("simulate_scenario", scenario_id="apt_campaign")
    return {"task_id": task_id}

    # later
    status = get_status(task_id)
"""
from __future__ import annotations

from .registry import enqueue, get_status, register_task, TaskStatus
from .config import RedisSettings, queue_settings

__all__ = [
    "enqueue",
    "get_status",
    "register_task",
    "TaskStatus",
    "RedisSettings",
    "queue_settings",
]
