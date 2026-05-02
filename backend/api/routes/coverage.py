"""MITRE ATT&CK detection coverage center endpoints."""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request

from backend.audit import log_action
from backend.auth import require_permission
from backend.cache import cache

from ..deps import _client_ip, limiter

logger = logging.getLogger("cybertwin.coverage")

router = APIRouter(tags=["coverage"])

_COVERAGE_CACHE_KEY = "coverage:snapshot"
_COVERAGE_CACHE_TTL = 30


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


def _compute_coverage_snapshot() -> dict[str, Any]:
    cached = cache.get(_COVERAGE_CACHE_KEY)
    if isinstance(cached, dict):
        return cached
    from backend.coverage.calculator import build_default_calculator
    calc = build_default_calculator()
    records, summary = calc.compute()
    snapshot = {
        "summary": summary.to_dict(),
        "records": [r.to_dict() for r in records],
    }
    try:
        cache.set(_COVERAGE_CACHE_KEY, snapshot, ttl=_COVERAGE_CACHE_TTL)
    except Exception as exc:
        logger.debug("Coverage cache write failed: %s", exc)
    return snapshot


@router.get("/api/coverage/summary")
@limiter.limit("60/minute")
def coverage_summary(request: Request, user=Depends(require_permission("view_results"))):
    return _compute_coverage_snapshot()["summary"]


@router.get("/api/coverage/mitre")
@limiter.limit("30/minute")
def coverage_mitre_table(
    request: Request,
    status: Optional[str] = None,
    tactic: Optional[str] = None,
    user=Depends(require_permission("view_results")),
):
    snap = _compute_coverage_snapshot()
    records = snap["records"]
    if status:
        records = [r for r in records if r["status"] == status]
    if tactic:
        records = [r for r in records if r["tactic_id"] == tactic]
    return {"total": len(records), "records": records}


@router.get("/api/coverage/technique/{technique_id}")
@limiter.limit("60/minute")
def coverage_technique_detail(
    request: Request, technique_id: str,
    user=Depends(require_permission("view_results")),
):
    snap = _compute_coverage_snapshot()
    for r in snap["records"]:
        if r["technique_id"] == technique_id:
            return r
    from fastapi import HTTPException
    raise HTTPException(404, f"Technique '{technique_id}' not found in catalog")


@router.get("/api/coverage/gaps")
@limiter.limit("30/minute")
def coverage_gaps(
    request: Request,
    high_risk_only: bool = False,
    limit: int = 50,
    user=Depends(require_permission("view_results")),
):
    snap = _compute_coverage_snapshot()
    from backend.coverage.gap_analyzer import GapAnalyzer
    from backend.coverage.models import TechniqueCoverage, TechniqueStatus

    typed_records = []
    for r in snap["records"]:
        typed_records.append(TechniqueCoverage(
            technique_id=r["technique_id"],
            name=r["name"],
            tactic_id=r["tactic_id"],
            tactic_name=r["tactic_name"],
            is_subtechnique=r["is_subtechnique"],
            rules=list(r.get("rules", [])),
            rule_count=r.get("rule_count", 0),
            scenarios=list(r.get("scenarios", [])),
            scenario_count=r.get("scenario_count", 0),
            last_simulation_id=r.get("last_simulation_id"),
            last_simulation_at=r.get("last_simulation_at"),
            last_simulation_detected=r.get("last_simulation_detected"),
            confidence=r.get("confidence", 0.0),
            required_logs=list(r.get("required_logs", [])),
            available_logs=list(r.get("available_logs", [])),
            missing_logs=list(r.get("missing_logs", [])),
            status=TechniqueStatus(r["status"]),
        ))

    gaps = GapAnalyzer(typed_records).analyse(only_high_risk=high_risk_only)
    gaps = gaps[: max(1, min(limit, 500))]
    return {"total": len(gaps), "gaps": [g.to_dict() for g in gaps]}


@router.get("/api/coverage/gaps/high-risk")
@limiter.limit("30/minute")
def coverage_high_risk_gaps(
    request: Request, limit: int = 25,
    user=Depends(require_permission("view_results")),
):
    return coverage_gaps(request=request, high_risk_only=True, limit=limit, user=user)


@router.post("/api/coverage/recalculate")
@limiter.limit("10/minute")
def coverage_recalculate(
    request: Request,
    user=Depends(require_permission("configure_system")),
):
    cache.delete(_COVERAGE_CACHE_KEY) if hasattr(cache, "delete") else None
    snap = _compute_coverage_snapshot()
    log_action("COVERAGE_RECALCULATE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               ip_address=_client_ip(request),
               details={"catalog_total": snap["summary"]["catalog_total"]})
    return {"status": "recalculated", "summary": snap["summary"]}
