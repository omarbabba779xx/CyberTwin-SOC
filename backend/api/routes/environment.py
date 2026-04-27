"""Read-only views over the simulated digital-twin environment."""

from __future__ import annotations

from fastapi import APIRouter, Request

from ..deps import limiter, orchestrator

router = APIRouter(tags=["environment"])


@router.get("/api/environment")
@limiter.limit("60/minute")
def get_environment(request: Request):
    return orchestrator.environment.to_dict()


@router.get("/api/environment/hosts")
@limiter.limit("60/minute")
def get_hosts(request: Request):
    return list(orchestrator.environment.get_hosts().values())


@router.get("/api/environment/users")
@limiter.limit("60/minute")
def get_users(request: Request):
    return list(orchestrator.environment.get_users().values())
