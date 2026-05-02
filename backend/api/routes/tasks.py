"""Background task endpoints.

Endpoints:
- GET    /api/tasks/{task_id}          - poll status (queued/running/succeeded/failed)
- GET    /api/tasks                    - list registered task types (admin)
- DELETE /api/tasks/{task_id}          - cancel (no-op for in-process executor today)

The execution backend is opaque to the API: today an in-process Arq-shaped
registry, in v3.2 a real Arq worker. Clients poll until status terminal.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.audit import log_action
from backend.auth import require_permission
from backend.jobs import get_status
from backend.jobs.registry import list_registered, _key, TaskStatus
from backend.cache import cache

from ..deps import _client_ip, limiter

# Force-import the task module so @register_task decorators run on import.
import backend.jobs.tasks  # noqa: F401

router = APIRouter(tags=["tasks"])


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


@router.get("/api/tasks/{task_id}")
@limiter.limit("120/minute")
def get_task_status(
    task_id: str, request: Request,
    user=Depends(require_permission("view_results")),
):
    status = get_status(task_id)
    if status is None:
        raise HTTPException(404, f"Task '{task_id}' not found or expired")
    return {"task_id": task_id, **status}


@router.get("/api/tasks")
@limiter.limit("60/minute")
def list_task_types(
    request: Request,
    user=Depends(require_permission("view_results")),
):
    return {"registered": list_registered()}


@router.delete("/api/tasks/{task_id}")
@limiter.limit("30/minute")
def cancel_task(
    task_id: str, request: Request,
    user=Depends(require_permission("simulation:run")),
):
    status = get_status(task_id)
    if status is None:
        raise HTTPException(404, f"Task '{task_id}' not found or expired")

    terminal = {TaskStatus.SUCCEEDED.value, TaskStatus.FAILED.value, TaskStatus.CANCELLED.value}
    if status.get("status") in terminal:
        return {"task_id": task_id, "status": status["status"], "note": "already terminal"}

    # In-process executor today: cancellation flips the status flag for any
    # cooperative task that polls it. Real Arq worker lands in v3.2.
    import json
    status["status"] = TaskStatus.CANCELLED.value
    cache.set(_key(task_id), json.dumps(status, default=str), ttl=86400)
    log_action("TASK_CANCEL", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=task_id, ip_address=_client_ip(request))
    return {"task_id": task_id, "status": TaskStatus.CANCELLED.value}
