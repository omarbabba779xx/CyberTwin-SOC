"""Task registry and lightweight in-process executor.

The API process can enqueue work without a worker being alive: tasks fall
back to immediate in-process execution (synchronous) and the result is
stored in the same Redis keyspace the future Arq worker will use. This
keeps endpoints uniformly async-shaped while we migrate workloads.

Status keys live under `cybertwin:task:{task_id}` with these fields:
- status   -> queued | running | succeeded | failed | cancelled
- result   -> JSON-encoded payload or null
- error    -> error string or null
- progress -> 0..100 integer
- enqueued_at, started_at, finished_at -> ISO-8601 UTC

This module is intentionally thin: it does NOT depend on Arq for the
default code path so tests stay hermetic and fast.
"""
from __future__ import annotations

import json
import secrets
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from backend.cache import cache


_TASKS: dict[str, Callable[..., Awaitable[Any]]] = {}


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


async def enqueue(task_name: str, **kwargs: Any) -> str:
    """Enqueue a task. Returns the task_id immediately.

    In v3.1.x there is no Arq worker; we execute in-process and persist
    results in Redis using the same key layout the future worker will use.
    Endpoints can already poll /api/tasks/{task_id} regardless.
    """
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
    except Exception as exc:  # noqa: BLE001 — we deliberately catch all
        _write(
            task_id,
            status=TaskStatus.FAILED.value,
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc()[-2000:],
            finished_at=_now_iso(),
        )
    return task_id


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
