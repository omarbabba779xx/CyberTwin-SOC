"""SOC Case Management - Alert -> Incident -> Case workflow.

A Case is the unit of analyst work. It can be opened from one alert, a
correlated incident, or manually. Comments, evidence, status changes and
SLA are tracked deterministically.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .database import get_conn
from .models import (
    Case, CaseComment, CaseEvidence, CaseSeverity, CaseStatus, SLA_HOURS,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_case_id() -> str:
    return f"CASE-{uuid.uuid4().hex[:8].upper()}"


def _serialise_lists(case: Case) -> tuple:
    return (
        json.dumps(case.alert_ids),
        json.dumps(case.incident_ids),
        json.dumps(case.affected_hosts),
        json.dumps(case.affected_users),
        json.dumps(case.mitre_techniques),
        json.dumps(case.tags),
    )


def _row_to_case(row: dict) -> Case:
    return Case(
        case_id=row["case_id"], tenant_id=row.get("tenant_id", "default"),
        title=row["title"],
        description=row["description"] or "",
        severity=row["severity"], status=row["status"],
        assignee=row["assignee"], created_by=row["created_by"],
        created_at=row["created_at"], updated_at=row["updated_at"],
        closed_at=row["closed_at"], closure_reason=row["closure_reason"],
        sla_due_at=row["sla_due_at"],
        alert_ids=json.loads(row["alert_ids"] or "[]"),
        incident_ids=json.loads(row["incident_ids"] or "[]"),
        affected_hosts=json.loads(row["affected_hosts"] or "[]"),
        affected_users=json.loads(row["affected_users"] or "[]"),
        mitre_techniques=json.loads(row["mitre_techniques"] or "[]"),
        tags=json.loads(row["tags"] or "[]"),
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

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
    """Open a new case. SLA due-date is computed from severity."""
    if severity not in {s.value for s in CaseSeverity}:
        raise ValueError(f"Invalid severity '{severity}'")
    if not title or len(title.strip()) < 3:
        raise ValueError("Case title must be at least 3 characters long.")

    sla_hours = SLA_HOURS.get(severity, 24)
    now_dt = datetime.now(timezone.utc)
    sla_due = (now_dt + timedelta(hours=sla_hours)).isoformat()
    now_iso = now_dt.isoformat()

    case = Case(
        case_id=_new_case_id(), tenant_id=tenant_id, title=title.strip(),
        description=description, severity=severity,
        status=CaseStatus.NEW.value, assignee=assignee,
        created_by=created_by, created_at=now_iso, updated_at=now_iso,
        sla_due_at=sla_due,
        alert_ids=alert_ids or [], incident_ids=incident_ids or [],
        affected_hosts=affected_hosts or [], affected_users=affected_users or [],
        mitre_techniques=mitre_techniques or [], tags=tags or [],
    )

    conn = get_conn()
    conn.execute("""
        INSERT INTO soc_cases
            (case_id, tenant_id, title, description, severity, status, assignee,
             created_by, created_at, updated_at, sla_due_at,
             alert_ids, incident_ids, affected_hosts, affected_users,
             mitre_techniques, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case.case_id, case.tenant_id, case.title, case.description, case.severity,
        case.status, case.assignee, case.created_by,
        case.created_at, case.updated_at, case.sla_due_at,
        *_serialise_lists(case),
    ))
    conn.commit()
    conn.close()
    return case


def get_case(
    case_id: str,
    *,
    with_relations: bool = True,
    tenant_id: str = "default",
) -> Optional[Case]:
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM soc_cases WHERE case_id = ? AND tenant_id = ?",
        (case_id, tenant_id),
    ).fetchone()
    if row is None:
        conn.close()
        return None
    case = _row_to_case(dict(row))

    if with_relations:
        cmt_rows = conn.execute(
            "SELECT * FROM case_comments WHERE case_id = ? AND tenant_id = ? ORDER BY comment_id ASC",
            (case_id, tenant_id),
        ).fetchall()
        case.comments = [CaseComment(**dict(r)) for r in cmt_rows]

        ev_rows = conn.execute(
            "SELECT * FROM case_evidence WHERE case_id = ? AND tenant_id = ? ORDER BY evidence_id ASC",
            (case_id, tenant_id),
        ).fetchall()
        case.evidence = []
        for r in ev_rows:
            d = dict(r)
            if d.get("payload"):
                try:
                    d["payload"] = json.loads(d["payload"])
                except (json.JSONDecodeError, TypeError):
                    pass
            case.evidence.append(CaseEvidence(**d))

    conn.close()
    return case


def list_cases(
    *, status: Optional[str] = None, severity: Optional[str] = None,
    assignee: Optional[str] = None, limit: int = 50,
    tenant_id: str = "default",
) -> list[Case]:
    sql = ["SELECT * FROM soc_cases WHERE tenant_id = ?"]
    params: list = [tenant_id]
    if status:
        sql.append("AND status = ?")
        params.append(status)
    if severity:
        sql.append("AND severity = ?")
        params.append(severity)
    if assignee:
        sql.append("AND assignee = ?")
        params.append(assignee)
    sql.append("ORDER BY created_at DESC LIMIT ?")
    params.append(limit)

    conn = get_conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [_row_to_case(dict(r)) for r in rows]


_UPDATABLE_COLUMNS: frozenset[str] = frozenset({
    "status", "severity", "assignee", "title", "description", "tags",
    "updated_at",
})
# Identifier whitelist regex used as defence-in-depth before any column name
# is composed into SQL via string interpolation.
_SQL_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def update_case(case_id: str, *, tenant_id: str = "default", **fields: Any) -> Optional[Case]:
    """Patch arbitrary scalar fields (status, severity, assignee, ...).

    Column names are filtered through ``_UPDATABLE_COLUMNS`` *and* a regex
    identifier pattern, so the f-string SQL composition is safe.
    """
    if not fields:
        return get_case(case_id, tenant_id=tenant_id)
    # Defence-in-depth: drop any unknown column AND verify it matches an
    # identifier pattern - never trust a single layer.
    fields = {
        k: v for k, v in fields.items()
        if k in _UPDATABLE_COLUMNS and _SQL_IDENT_RE.match(k)
    }
    if not fields:
        return get_case(case_id, tenant_id=tenant_id)
    if "tags" in fields:
        fields["tags"] = json.dumps(fields["tags"])
    fields["updated_at"] = _now()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    params = list(fields.values()) + [case_id, tenant_id]
    conn = get_conn()
    cur = conn.execute(
        # Column names come from _UPDATABLE_COLUMNS allowlist + regex.
        f"UPDATE soc_cases SET {set_clause} WHERE case_id = ? AND tenant_id = ?",  # nosec B608
        params,
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return None
    return get_case(case_id, tenant_id=tenant_id)


def assign_case(case_id: str, *, assignee: str, tenant_id: str = "default") -> Optional[Case]:
    return update_case(
        case_id,
        tenant_id=tenant_id,
        assignee=assignee,
        status=CaseStatus.IN_PROGRESS.value,
    )


def close_case(
    case_id: str, *, closure_reason: str,
    final_status: str = CaseStatus.CLOSED.value,
    tenant_id: str = "default",
) -> Optional[Case]:
    if final_status not in {CaseStatus.CLOSED.value,
                            CaseStatus.RESOLVED.value,
                            CaseStatus.FALSE_POSITIVE.value}:
        raise ValueError(f"Invalid final_status '{final_status}'")
    if not closure_reason or len(closure_reason.strip()) < 5:
        raise ValueError("A closure_reason of at least 5 characters is required.")

    now_iso = _now()
    conn = get_conn()
    cur = conn.execute("""
        UPDATE soc_cases
        SET status = ?, closed_at = ?, closure_reason = ?, updated_at = ?
        WHERE case_id = ? AND tenant_id = ?
    """, (final_status, now_iso, closure_reason, now_iso, case_id, tenant_id))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return None
    return get_case(case_id, tenant_id=tenant_id)


def add_comment(
    case_id: str,
    *,
    author: str,
    role: str,
    body: str,
    tenant_id: str = "default",
) -> CaseComment:
    if not body or not body.strip():
        raise ValueError("Comment body is required.")
    if get_case(case_id, with_relations=False, tenant_id=tenant_id) is None:
        raise ValueError(f"Case '{case_id}' not found.")

    ts = _now()
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO case_comments (case_id, tenant_id, author, role, body, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (case_id, tenant_id, author, role, body.strip(), ts))
    cid = cur.lastrowid
    conn.execute(
        "UPDATE soc_cases SET updated_at = ? WHERE case_id = ? AND tenant_id = ?",
        (ts, case_id, tenant_id),
    )
    conn.commit()
    conn.close()
    return CaseComment(comment_id=cid, case_id=case_id, tenant_id=tenant_id, author=author,
                       role=role, body=body.strip(), timestamp=ts)


def add_evidence(
    case_id: str, *, type: str, reference: str,
    description: str = "", added_by: str,
    payload: Optional[dict[str, Any]] = None,
    tenant_id: str = "default",
) -> CaseEvidence:
    if get_case(case_id, with_relations=False, tenant_id=tenant_id) is None:
        raise ValueError(f"Case '{case_id}' not found.")
    if not reference:
        raise ValueError("Evidence reference is required.")

    ts = _now()
    payload_json = json.dumps(payload, default=str) if payload else None
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO case_evidence (case_id, type, reference, description,
                                   added_by, timestamp, payload, tenant_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, type, reference, description, added_by, ts, payload_json, tenant_id))
    eid = cur.lastrowid
    conn.execute(
        "UPDATE soc_cases SET updated_at = ? WHERE case_id = ? AND tenant_id = ?",
        (ts, case_id, tenant_id),
    )
    conn.commit()
    conn.close()
    return CaseEvidence(evidence_id=eid, case_id=case_id, tenant_id=tenant_id, type=type,
                        reference=reference, description=description,
                        added_by=added_by, timestamp=ts, payload=payload)
