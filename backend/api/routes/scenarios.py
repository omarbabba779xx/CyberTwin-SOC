"""Scenario catalogue and custom scenario management."""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from typing import Optional

from backend.audit import log_action
from backend.auth import require_permission

from ..deps import PROJECT_ROOT, _client_ip, _safe_path, limiter, orchestrator as _orchestrator

router = APIRouter(tags=["scenarios"])


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


def _tenant_slug(tenant_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", tenant_id)[:48] or "default"


def _scenario_visible_to_tenant(scenario: dict, tenant_id: str) -> bool:
    owner = scenario.get("tenant_id")
    return owner in (None, "", "global", tenant_id)


class CustomScenarioRequest(BaseModel):
    id: Optional[str] = None
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=4000)
    severity: str = "medium"
    category: str = Field(default="custom", max_length=80)
    phases: list = Field(default_factory=list, max_length=50)

    @field_validator("id", mode="before")
    @classmethod
    def _sanitise_id(cls, v):
        if v is None:
            return v
        sanitised = re.sub(r"[^a-zA-Z0-9\-_]", "", str(v))[:64]
        if not sanitised:
            raise ValueError("Invalid scenario id")
        return sanitised

    @field_validator("severity")
    @classmethod
    def _severity_valid(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v


@router.get("/api/scenarios")
@limiter.limit("60/minute")
def list_scenarios(request: Request, user=Depends(require_permission("view_results"))):
    tenant = _tenant_id(user)
    return [
        scenario for scenario in _orchestrator.attack_engine.list_scenarios()
        if _scenario_visible_to_tenant(scenario, tenant)
    ]


@router.get("/api/scenarios/{scenario_id}")
@limiter.limit("60/minute")
def get_scenario(
    request: Request,
    scenario_id: str,
    user=Depends(require_permission("view_results")),
):
    scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
    if scenario is None or not _scenario_visible_to_tenant(scenario, _tenant_id(user)):
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario


@router.post("/api/scenarios/custom")
@limiter.limit("10/minute")
def save_custom_scenario(
    request: Request,
    scenario: CustomScenarioRequest,
    user=Depends(require_permission("manage_scenarios")),
):
    tenant = _tenant_id(user)
    custom_dir = PROJECT_ROOT / "scenarios" / "custom" / _tenant_slug(tenant)
    custom_dir.mkdir(parents=True, exist_ok=True)
    requested_id = scenario.id or f"sc-custom-{len(list(custom_dir.glob('*.json'))) + 1:03d}"
    sid = f"{_tenant_slug(tenant)}-{requested_id}"[:80].rstrip("-")
    filepath = _safe_path(custom_dir, sid, ".json")
    data = scenario.model_dump()
    data["id"] = sid
    data["tenant_id"] = tenant
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    _orchestrator.attack_engine.load_scenarios()
    log_action("CREATE_SCENARIO", username=user["sub"], role=user.get("role"),
               tenant_id=tenant,
               resource=sid, ip_address=_client_ip(request))
    return {"status": "saved", "id": sid}
