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
def list_scenarios(request: Request):
    return _orchestrator.attack_engine.list_scenarios()


@router.get("/api/scenarios/{scenario_id}")
@limiter.limit("60/minute")
def get_scenario(request: Request, scenario_id: str):
    scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario


@router.post("/api/scenarios/custom")
@limiter.limit("10/minute")
def save_custom_scenario(
    request: Request,
    scenario: CustomScenarioRequest,
    user=Depends(require_permission("manage_scenarios")),
):
    custom_dir = PROJECT_ROOT / "scenarios" / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    sid = scenario.id or f"sc-custom-{len(list(custom_dir.glob('*.json'))) + 1:03d}"
    filepath = _safe_path(custom_dir, sid, ".json")
    data = scenario.model_dump()
    data["id"] = sid
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    _orchestrator.attack_engine.load_scenarios()
    log_action("CREATE_SCENARIO", username=user["sub"], role=user.get("role"),
               resource=sid, ip_address=_client_ip(request))
    return {"status": "saved", "id": sid}
