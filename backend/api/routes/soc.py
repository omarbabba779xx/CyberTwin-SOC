"""SOC workflow endpoints: alert feedback, case management, suppressions."""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from backend.audit import log_action
from backend.auth import require_permission

from ..deps import _client_ip, limiter

router = APIRouter(tags=["soc"])


def _approx_size(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str))
    except Exception:
        return 65 * 1024


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class FeedbackRequest(BaseModel):
    rule_id: str = Field(min_length=1, max_length=120)
    verdict: str
    reason: str = Field(default="", max_length=2000)

    @field_validator("verdict")
    @classmethod
    def _verdict_valid(cls, v):
        from backend.soc.models import AlertVerdict
        if v not in {a.value for a in AlertVerdict}:
            raise ValueError(f"verdict must be one of {[a.value for a in AlertVerdict]}")
        return v


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: str = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    incident_ids: list[str] = Field(default_factory=list, max_length=100)
    affected_hosts: list[str] = Field(default_factory=list, max_length=100)
    affected_users: list[str] = Field(default_factory=list, max_length=100)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=50)
    assignee: Optional[str] = Field(default=None, max_length=120)

    @field_validator("severity")
    @classmethod
    def _case_severity_valid(cls, v: str) -> str:
        from backend.soc.models import CaseSeverity
        if v not in {s.value for s in CaseSeverity}:
            raise ValueError(f"severity must be one of {[s.value for s in CaseSeverity]}")
        return v

    @field_validator("alert_ids", "incident_ids", "affected_hosts", "affected_users",
                     "mitre_techniques", "tags")
    @classmethod
    def _case_list_items_bounded(cls, v: list[str]) -> list[str]:
        if any(len(str(item)) > 160 for item in v):
            raise ValueError("list item exceeds 160 characters")
        return v


class CasePatchRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    severity: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = Field(default=None, max_length=120)
    tags: Optional[list[str]] = Field(default=None, max_length=50)

    @field_validator("severity")
    @classmethod
    def _patch_severity_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from backend.soc.models import CaseSeverity
        if v not in {s.value for s in CaseSeverity}:
            raise ValueError(f"severity must be one of {[s.value for s in CaseSeverity]}")
        return v

    @field_validator("status")
    @classmethod
    def _patch_status_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from backend.soc.models import CaseStatus
        if v not in {s.value for s in CaseStatus}:
            raise ValueError(f"status must be one of {[s.value for s in CaseStatus]}")
        return v


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class EvidenceRequest(BaseModel):
    type: str = Field(default="alert", max_length=40)
    reference: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=3000)
    payload: Optional[dict[str, Any]] = None

    @field_validator("type")
    @classmethod
    def _evidence_type_valid(cls, v: str) -> str:
        allowed = {"alert", "event", "ioc", "file", "url", "note"}
        if v not in allowed:
            raise ValueError(f"type must be one of {sorted(allowed)}")
        return v

    @field_validator("payload")
    @classmethod
    def _payload_size_cap(cls, v: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if v is not None and _approx_size(v) > 64 * 1024:
            raise ValueError("payload exceeds 64 KB cap")
        return v


class CaseCloseRequest(BaseModel):
    closure_reason: str = Field(min_length=5, max_length=3000)
    final_status: str = "closed"

    @field_validator("final_status")
    @classmethod
    def _final_status_valid(cls, v: str) -> str:
        allowed = {"closed", "resolved", "false_positive"}
        if v not in allowed:
            raise ValueError(f"final_status must be one of {sorted(allowed)}")
        return v


class AssignRequest(BaseModel):
    assignee: str = Field(min_length=1, max_length=120)


class SuppressionRequest(BaseModel):
    scope: str
    target: str = Field(min_length=1, max_length=250)
    reason: str = Field(min_length=5, max_length=2000)
    duration_hours: Optional[int] = Field(default=None, ge=1, le=24 * 90)
    expires_at: Optional[str] = Field(default=None, max_length=80)
    approved_by: Optional[str] = Field(default=None, max_length=120)

    @field_validator("scope")
    @classmethod
    def _suppression_scope_valid(cls, v: str) -> str:
        from backend.soc.models import SuppressionScope
        if v not in {s.value for s in SuppressionScope}:
            raise ValueError(f"scope must be one of {[s.value for s in SuppressionScope]}")
        return v


# ---------------------------------------------------------------------------
# Alert feedback
# ---------------------------------------------------------------------------

@router.post("/api/alerts/{alert_id}/feedback")
@limiter.limit("60/minute")
def post_alert_feedback(
    alert_id: str, payload: FeedbackRequest, request: Request,
    user=Depends(require_permission("feedback:write")),
):
    from backend.soc import record_feedback
    try:
        fb = record_feedback(
            alert_id=alert_id, rule_id=payload.rule_id,
            verdict=payload.verdict, reason=payload.reason,
            analyst=user["sub"], role=user.get("role", "viewer"),
            tenant_id=_tenant_id(user),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("ALERT_FEEDBACK", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=alert_id, ip_address=_client_ip(request),
               details={"rule_id": payload.rule_id, "verdict": payload.verdict})
    return fb.to_dict()


@router.get("/api/alerts/feedback/summary")
@limiter.limit("60/minute")
def get_feedback_summary(request: Request, user=Depends(require_permission("view_results"))):
    from backend.soc import feedback_summary
    return feedback_summary(tenant_id=_tenant_id(user))


@router.get("/api/alerts/feedback/noisy-rules")
@limiter.limit("30/minute")
def get_noisy_rules(
    request: Request, min_total: int = 3, threshold: float = 0.5,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import list_noisy_rules
    return {
        "rules": list_noisy_rules(
            min_total=min_total,
            fp_threshold=threshold,
            tenant_id=_tenant_id(user),
        )
    }


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@router.post("/api/cases")
@limiter.limit("30/minute")
def post_case(payload: CaseCreateRequest, request: Request,
              user=Depends(require_permission("case:write"))):
    from backend.soc import create_case
    try:
        case = create_case(
            title=payload.title, description=payload.description,
            severity=payload.severity, created_by=user["sub"],
            alert_ids=payload.alert_ids, incident_ids=payload.incident_ids,
            affected_hosts=payload.affected_hosts,
            affected_users=payload.affected_users,
            mitre_techniques=payload.mitre_techniques,
            tags=payload.tags, assignee=payload.assignee,
            tenant_id=_tenant_id(user),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("CASE_CREATE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=case.case_id, ip_address=_client_ip(request),
               details={"severity": case.severity})
    return case.to_dict()


@router.get("/api/cases")
@limiter.limit("60/minute")
def list_cases_endpoint(
    request: Request,
    status: Optional[str] = None, severity: Optional[str] = None,
    assignee: Optional[str] = None, limit: int = 50,
    user=Depends(require_permission("case:read")),
):
    from backend.soc import list_cases
    cases = list_cases(
        status=status,
        severity=severity,
        assignee=assignee,
        limit=limit,
        tenant_id=_tenant_id(user),
    )
    return {"total": len(cases), "cases": [c.to_dict() for c in cases]}


@router.get("/api/cases/{case_id}")
@limiter.limit("60/minute")
def get_case_endpoint(case_id: str, request: Request,
                      user=Depends(require_permission("case:read"))):
    from backend.soc import get_case
    case = get_case(case_id, tenant_id=_tenant_id(user))
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    return case.to_dict()


@router.patch("/api/cases/{case_id}")
@limiter.limit("60/minute")
def patch_case(case_id: str, payload: CasePatchRequest, request: Request,
               user=Depends(require_permission("case:write"))):
    from backend.soc import update_case
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    case = update_case(case_id, tenant_id=_tenant_id(user), **fields)
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_UPDATE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=case_id, ip_address=_client_ip(request),
               details={"changes": list(fields.keys())})
    return case.to_dict()


@router.post("/api/cases/{case_id}/comments")
@limiter.limit("60/minute")
def post_case_comment(case_id: str, payload: CommentRequest, request: Request,
                      user=Depends(require_permission("case:write"))):
    from backend.soc import add_comment
    try:
        cmt = add_comment(case_id, author=user["sub"],
                          role=user.get("role", "viewer"), body=payload.body,
                          tenant_id=_tenant_id(user))
    except ValueError as exc:
        raise HTTPException(404 if "not found" in str(exc) else 400, str(exc))
    return cmt.to_dict()


@router.post("/api/cases/{case_id}/evidence")
@limiter.limit("60/minute")
def post_case_evidence(case_id: str, payload: EvidenceRequest, request: Request,
                       user=Depends(require_permission("case:write"))):
    from backend.soc import add_evidence
    try:
        ev = add_evidence(case_id, type=payload.type, reference=payload.reference,
                          description=payload.description,
                          added_by=user["sub"], payload=payload.payload,
                          tenant_id=_tenant_id(user))
    except ValueError as exc:
        raise HTTPException(404 if "not found" in str(exc) else 400, str(exc))
    return ev.to_dict()


@router.post("/api/cases/{case_id}/assign")
@limiter.limit("30/minute")
def post_case_assign(case_id: str, payload: AssignRequest, request: Request,
                     user=Depends(require_permission("case:assign"))):
    from backend.soc import assign_case
    case = assign_case(case_id, assignee=payload.assignee, tenant_id=_tenant_id(user))
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_ASSIGN", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=case_id, ip_address=_client_ip(request),
               details={"assignee": payload.assignee})
    return case.to_dict()


@router.post("/api/cases/{case_id}/close")
@limiter.limit("30/minute")
def post_case_close(case_id: str, payload: CaseCloseRequest, request: Request,
                    user=Depends(require_permission("case:close"))):
    from backend.soc import close_case
    try:
        case = close_case(case_id, closure_reason=payload.closure_reason,
                          final_status=payload.final_status,
                          tenant_id=_tenant_id(user))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_CLOSE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=case_id, ip_address=_client_ip(request),
               details={"final_status": payload.final_status})
    return case.to_dict()


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

@router.post("/api/suppressions")
@limiter.limit("20/minute")
def post_suppression(payload: SuppressionRequest, request: Request,
                     user=Depends(require_permission("suppression:create"))):
    from backend.soc import create_suppression
    try:
        s = create_suppression(
            scope=payload.scope, target=payload.target,
            reason=payload.reason, duration_hours=payload.duration_hours,
            expires_at=payload.expires_at, created_by=user["sub"],
            approved_by=payload.approved_by,
            tenant_id=_tenant_id(user),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("SUPPRESSION_CREATE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               ip_address=_client_ip(request),
               details={"scope": s.scope, "target": s.target, "expires_at": s.expires_at})
    return s.to_dict()


@router.get("/api/suppressions")
@limiter.limit("60/minute")
def get_suppressions(request: Request, only_active: bool = True,
                     user=Depends(require_permission("view_results"))):
    from backend.soc import list_suppressions
    items = list_suppressions(only_active=only_active, tenant_id=_tenant_id(user))
    return {"total": len(items), "suppressions": [s.to_dict() for s in items]}


@router.delete("/api/suppressions/{suppression_id}")
@limiter.limit("20/minute")
def delete_suppression_endpoint(suppression_id: int, request: Request,
                                user=Depends(require_permission("suppression:delete"))):
    from backend.soc import delete_suppression
    if not delete_suppression(
        suppression_id,
        deleted_by=user["sub"],
        tenant_id=_tenant_id(user),
    ):
        raise HTTPException(404, f"Suppression #{suppression_id} not found")
    log_action("SUPPRESSION_DELETE", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               resource=str(suppression_id), ip_address=_client_ip(request))
    return {"status": "deleted", "suppression_id": suppression_id}
