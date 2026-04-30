"""Persisted simulation history (SQLite-backed)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.audit import log_action
from backend.auth import require_permission
from backend.database import (
    delete_run,
    get_run,
    get_runs,
    get_runs_by_scenario,
    get_stats,
)

from ..deps import _client_ip, limiter

router = APIRouter(tags=["history"])


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


@router.get("/api/history")
@limiter.limit("60/minute")
def list_history(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    user=Depends(require_permission("view_results")),
):
    return get_runs(limit, tenant_id=_tenant_id(user))


@router.get("/api/history/stats")
@limiter.limit("60/minute")
def history_stats(
    request: Request,
    user=Depends(require_permission("view_results")),
):
    return get_stats(tenant_id=_tenant_id(user))


@router.get("/api/history/scenario/{scenario_id}")
@limiter.limit("60/minute")
def history_by_scenario(
    request: Request,
    scenario_id: str,
    user=Depends(require_permission("view_results")),
):
    return get_runs_by_scenario(scenario_id, tenant_id=_tenant_id(user))


@router.get("/api/history/{run_id}")
@limiter.limit("60/minute")
def history_detail(
    request: Request,
    run_id: int,
    user=Depends(require_permission("view_results")),
):
    run = get_run(run_id, tenant_id=_tenant_id(user))
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@router.delete("/api/history/{run_id}")
@limiter.limit("30/minute")
def history_delete(
    request: Request,
    run_id: int,
    user=Depends(require_permission("delete_history")),
):
    delete_run(run_id, tenant_id=_tenant_id(user))
    log_action(
        "DELETE_HISTORY",
        username=user["sub"],
        role=user.get("role"),
        resource=str(run_id),
        ip_address=_client_ip(request),
    )
    return {"status": "deleted"}
