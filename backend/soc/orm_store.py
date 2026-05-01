"""SQLAlchemy-backed SOC runtime store.

This module mirrors the SQLite SOC operations with the production DATABASE_URL
engine. It keeps API-facing dataclasses stable while using PostgreSQL-ready ORM
tables for cases, comments, evidence, feedback, and suppressions.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc

from backend.db.models import (
    AlertFeedback as ORMAlertFeedback,
    CaseComment as ORMCaseComment,
    CaseEvidence as ORMCaseEvidence,
    SocCase as ORMSocCase,
    Suppression as ORMSuppression,
)
from backend.db.session import SessionLocal

from .models import (
    AlertFeedback, AlertVerdict, Case, CaseComment, CaseEvidence,
    CaseSeverity, CaseStatus, SLA_HOURS, Suppression, SuppressionScope,
)


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _new_case_id() -> str:
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


def _new_ref(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _case_to_dc(row: ORMSocCase, *, comments=None, evidence=None) -> Case:
    return Case(
        case_id=row.case_id,
        tenant_id=row.tenant_id or "default",
        title=row.title,
        description=row.description or "",
        severity=row.severity,
        status=row.status,
        assignee=row.assignee,
        created_by=row.created_by,
        created_at=_iso(row.created_at),
        updated_at=_iso(row.updated_at),
        closed_at=_iso(row.closed_at) if row.closed_at else None,
        closure_reason=row.closure_reason,
        sla_due_at=_iso(row.sla_due_at) if row.sla_due_at else None,
        alert_ids=row.alert_ids_json or [],
        incident_ids=row.incident_ids_json or [],
        affected_hosts=row.affected_hosts_json or [],
        affected_users=row.affected_users_json or [],
        mitre_techniques=row.mitre_techniques_json or [],
        tags=row.tags_json or [],
        comments=comments or [],
        evidence=evidence or [],
    )


def _comment_to_dc(row: ORMCaseComment) -> CaseComment:
    return CaseComment(
        comment_id=row.id,
        case_id=row.case_id,
        tenant_id=row.tenant_id or "default",
        author=row.author,
        role=row.role or "",
        body=row.body,
        timestamp=_iso(row.created_at),
    )


def _evidence_to_dc(row: ORMCaseEvidence) -> CaseEvidence:
    return CaseEvidence(
        evidence_id=row.id,
        case_id=row.case_id,
        tenant_id=row.tenant_id or "default",
        type=row.type,
        reference=row.reference,
        description=row.description or "",
        added_by=row.added_by,
        timestamp=_iso(row.added_at),
        payload=row.payload,
    )


def _feedback_to_dc(row: ORMAlertFeedback) -> AlertFeedback:
    return AlertFeedback(
        feedback_id=row.id,
        tenant_id=row.tenant_id or "default",
        alert_id=row.alert_id,
        rule_id=row.rule_id,
        verdict=row.verdict,
        reason=row.reason or "",
        analyst=row.analyst,
        role=row.role or "",
        timestamp=_iso(row.created_at),
    )


def _suppression_to_dc(row: ORMSuppression) -> Suppression:
    return Suppression(
        suppression_id=row.id,
        tenant_id=row.tenant_id or "default",
        scope=row.scope,
        target=row.target,
        reason=row.reason,
        created_by=row.created_by,
        created_at=_iso(row.created_at),
        expires_at=row.expires_at or "",
        active=bool(row.active),
        approved_by=row.approved_by,
    )


def create_case(
    *, title: str, description: str = "",
    severity: str = CaseSeverity.MEDIUM.value,
    created_by: str,
    alert_ids: Optional[list[str]] = None,
    incident_ids: Optional[list[str]] = None,
    affected_hosts: Optional[list[str]] = None,
    affected_users: Optional[list[str]] = None,
    mitre_techniques: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    assignee: Optional[str] = None,
    tenant_id: str = "default",
) -> Case:
    if severity not in {s.value for s in CaseSeverity}:
        raise ValueError(f"Invalid severity '{severity}'")
    if not title or len(title.strip()) < 3:
        raise ValueError("Case title must be at least 3 characters long.")

    now = _now_dt()
    row = ORMSocCase(
        case_id=_new_case_id(),
        tenant_id=tenant_id,
        title=title.strip(),
        description=description,
        severity=severity,
        status=CaseStatus.NEW.value,
        assignee=assignee,
        created_by=created_by,
        created_at=now,
        updated_at=now,
        sla_due_at=now + timedelta(hours=SLA_HOURS.get(severity, 24)),
        alert_ids_json=alert_ids or [],
        incident_ids_json=incident_ids or [],
        affected_hosts_json=affected_hosts or [],
        affected_users_json=affected_users or [],
        mitre_techniques_json=mitre_techniques or [],
        tags_json=tags or [],
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        return _case_to_dc(row)


def get_case(case_id: str, *, with_relations: bool = True,
             tenant_id: str = "default") -> Optional[Case]:
    with SessionLocal() as db:
        row = db.query(ORMSocCase).filter_by(case_id=case_id, tenant_id=tenant_id).one_or_none()
        if row is None:
            return None
        comments: list[CaseComment] = []
        evidence: list[CaseEvidence] = []
        if with_relations:
            comments = [
                _comment_to_dc(r)
                for r in db.query(ORMCaseComment)
                .filter_by(case_id=case_id, tenant_id=tenant_id)
                .order_by(ORMCaseComment.id.asc())
                .all()
            ]
            evidence = [
                _evidence_to_dc(r)
                for r in db.query(ORMCaseEvidence)
                .filter_by(case_id=case_id, tenant_id=tenant_id)
                .order_by(ORMCaseEvidence.id.asc())
                .all()
            ]
        return _case_to_dc(row, comments=comments, evidence=evidence)


def list_cases(
    *, status: Optional[str] = None, severity: Optional[str] = None,
    assignee: Optional[str] = None, limit: int = 50,
    tenant_id: str = "default",
) -> list[Case]:
    with SessionLocal() as db:
        q = db.query(ORMSocCase).filter_by(tenant_id=tenant_id)
        if status:
            q = q.filter(ORMSocCase.status == status)
        if severity:
            q = q.filter(ORMSocCase.severity == severity)
        if assignee:
            q = q.filter(ORMSocCase.assignee == assignee)
        rows = q.order_by(desc(ORMSocCase.created_at)).limit(limit).all()
        return [_case_to_dc(r) for r in rows]


def update_case(case_id: str, *, tenant_id: str = "default", **fields: Any) -> Optional[Case]:
    allowed = {"status", "severity", "assignee", "title", "description", "tags"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    with SessionLocal() as db:
        row = db.query(ORMSocCase).filter_by(case_id=case_id, tenant_id=tenant_id).one_or_none()
        if row is None:
            return None
        for key, value in fields.items():
            setattr(row, "tags_json" if key == "tags" else key, value)
        row.updated_at = _now_dt()
        db.commit()
        return get_case(case_id, tenant_id=tenant_id)


def assign_case(case_id: str, *, assignee: str, tenant_id: str = "default") -> Optional[Case]:
    return update_case(case_id, tenant_id=tenant_id, assignee=assignee, status=CaseStatus.IN_PROGRESS.value)


def close_case(
    case_id: str, *, closure_reason: str,
    final_status: str = CaseStatus.CLOSED.value,
    tenant_id: str = "default",
) -> Optional[Case]:
    if final_status not in {CaseStatus.CLOSED.value, CaseStatus.RESOLVED.value, CaseStatus.FALSE_POSITIVE.value}:
        raise ValueError(f"Invalid final_status '{final_status}'")
    if not closure_reason or len(closure_reason.strip()) < 5:
        raise ValueError("A closure_reason of at least 5 characters is required.")
    with SessionLocal() as db:
        row = db.query(ORMSocCase).filter_by(case_id=case_id, tenant_id=tenant_id).one_or_none()
        if row is None:
            return None
        now = _now_dt()
        row.status = final_status
        row.closed_at = now
        row.closure_reason = closure_reason
        row.updated_at = now
        db.commit()
    return get_case(case_id, tenant_id=tenant_id)


def add_comment(
    case_id: str, *, author: str, role: str, body: str,
    tenant_id: str = "default",
) -> CaseComment:
    if not body or not body.strip():
        raise ValueError("Comment body is required.")
    with SessionLocal() as db:
        case = db.query(ORMSocCase).filter_by(case_id=case_id, tenant_id=tenant_id).one_or_none()
        if case is None:
            raise ValueError(f"Case '{case_id}' not found.")
        row = ORMCaseComment(
            comment_id=_new_ref("CMT"),
            case_id=case_id,
            tenant_id=tenant_id,
            author=author,
            role=role,
            body=body.strip(),
            created_at=_now_dt(),
        )
        case.updated_at = row.created_at
        db.add(row)
        db.commit()
        db.refresh(row)
        return _comment_to_dc(row)


def add_evidence(
    case_id: str, *, type: str, reference: str,
    description: str = "", added_by: str,
    payload: Optional[dict[str, Any]] = None,
    tenant_id: str = "default",
) -> CaseEvidence:
    if not reference:
        raise ValueError("Evidence reference is required.")
    with SessionLocal() as db:
        case = db.query(ORMSocCase).filter_by(case_id=case_id, tenant_id=tenant_id).one_or_none()
        if case is None:
            raise ValueError(f"Case '{case_id}' not found.")
        row = ORMCaseEvidence(
            evidence_id=_new_ref("EVD"),
            case_id=case_id,
            tenant_id=tenant_id,
            type=type,
            reference=reference,
            description=description,
            added_by=added_by,
            added_at=_now_dt(),
            payload=payload,
        )
        case.updated_at = row.added_at
        db.add(row)
        db.commit()
        db.refresh(row)
        return _evidence_to_dc(row)


def record_feedback(
    *, alert_id: str, rule_id: str, verdict: str,
    analyst: str, role: str, reason: str = "",
    tenant_id: str = "default",
) -> AlertFeedback:
    if verdict not in {v.value for v in AlertVerdict}:
        raise ValueError(f"Invalid verdict '{verdict}'. Allowed: {[v.value for v in AlertVerdict]}")
    row = ORMAlertFeedback(
        feedback_id=_new_ref("FDB"),
        alert_id=alert_id,
        rule_id=rule_id,
        tenant_id=tenant_id,
        analyst=analyst,
        role=role,
        verdict=verdict,
        reason=reason,
        created_at=_now_dt(),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        return _feedback_to_dc(row)


def list_feedback(
    *, alert_id: Optional[str] = None, rule_id: Optional[str] = None,
    limit: int = 100, tenant_id: str = "default",
) -> list[AlertFeedback]:
    with SessionLocal() as db:
        q = db.query(ORMAlertFeedback).filter_by(tenant_id=tenant_id)
        if alert_id:
            q = q.filter(ORMAlertFeedback.alert_id == alert_id)
        if rule_id:
            q = q.filter(ORMAlertFeedback.rule_id == rule_id)
        return [_feedback_to_dc(r) for r in q.order_by(desc(ORMAlertFeedback.id)).limit(limit).all()]


def feedback_summary(*, tenant_id: str = "default") -> dict[str, Any]:
    rows = list_feedback(tenant_id=tenant_id, limit=100000)
    by_verdict: dict[str, int] = defaultdict(int)
    for row in rows:
        by_verdict[row.verdict] += 1
    total = sum(by_verdict.values())
    fp = by_verdict.get(AlertVerdict.FALSE_POSITIVE.value, 0)
    tp = by_verdict.get(AlertVerdict.TRUE_POSITIVE.value, 0)
    return {
        "total_feedback": total,
        "by_verdict": dict(by_verdict),
        "false_positive_rate": round(fp / total, 4) if total else 0.0,
        "true_positive_rate": round(tp / total, 4) if total else 0.0,
    }


def list_noisy_rules(*, min_total: int = 3, fp_threshold: float = 0.5,
                     limit: int = 25, tenant_id: str = "default") -> list[dict[str, Any]]:
    rows = list_feedback(tenant_id=tenant_id, limit=100000)
    by_rule: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        by_rule[row.rule_id][row.verdict] += 1
    out: list[dict[str, Any]] = []
    for rule_id, vmap in by_rule.items():
        total = sum(vmap.values())
        if total < min_total:
            continue
        fp = vmap.get(AlertVerdict.FALSE_POSITIVE.value, 0)
        bp = vmap.get(AlertVerdict.BENIGN_POSITIVE.value, 0)
        rate = (fp + bp) / total
        if rate >= fp_threshold:
            out.append({
                "rule_id": rule_id,
                "total_feedback": total,
                "false_positive": fp,
                "benign_positive": bp,
                "noise_rate": round(rate, 3),
                "by_verdict": dict(vmap),
            })
    out.sort(key=lambda item: item["noise_rate"], reverse=True)
    return out[:limit]


def create_suppression(
    *, scope: str, target: str, reason: str,
    created_by: str, expires_at: Optional[str] = None,
    duration_hours: Optional[int] = None,
    approved_by: Optional[str] = None,
    tenant_id: str = "default",
) -> Suppression:
    if scope not in {s.value for s in SuppressionScope}:
        raise ValueError(f"Invalid scope '{scope}'. Allowed: {[s.value for s in SuppressionScope]}")
    if not target:
        raise ValueError("Suppression target is required.")
    if not reason or len(reason.strip()) < 5:
        raise ValueError("A meaningful reason (>= 5 chars) is required.")
    if not expires_at and not duration_hours:
        raise ValueError("Suppressions MUST expire. Provide expires_at (ISO) or duration_hours.")
    if not expires_at:
        expires_at = (_now_dt() + timedelta(hours=duration_hours)).isoformat()
    else:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt <= _now_dt():
            raise ValueError("expires_at must be in the future.")
        expires_at = exp_dt.isoformat()

    row = ORMSuppression(
        tenant_id=tenant_id,
        scope=scope,
        target=target,
        reason=reason,
        created_by=created_by,
        created_at=_now_dt(),
        expires_at=expires_at,
        active=True,
        approved_by=approved_by,
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        return _suppression_to_dc(row)


def list_suppressions(*, only_active: bool = True, tenant_id: str = "default") -> list[Suppression]:
    with SessionLocal() as db:
        q = db.query(ORMSuppression).filter_by(tenant_id=tenant_id)
        if only_active:
            q = q.filter(ORMSuppression.active.is_(True), ORMSuppression.expires_at > _now_dt().isoformat())
        return [_suppression_to_dc(r) for r in q.order_by(desc(ORMSuppression.id)).all()]


def delete_suppression(
    suppression_id: int, *, deleted_by: str,
    tenant_id: str = "default",
) -> bool:
    with SessionLocal() as db:
        row = db.query(ORMSuppression).filter_by(id=suppression_id, tenant_id=tenant_id).one_or_none()
        if row is None:
            return False
        row.active = False
        db.commit()
        return True
