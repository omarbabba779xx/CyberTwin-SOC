"""Models, enums, and dataclasses for the SOC module."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AlertVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    DUPLICATE = "duplicate"
    NEEDS_MORE_DATA = "needs_more_data"
    ESCALATED = "escalated"
    CLOSED = "closed"


class CaseStatus(str, Enum):
    NEW = "new"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class CaseSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SuppressionScope(str, Enum):
    RULE = "rule"
    USER = "user"
    HOST = "host"
    IP = "ip"
    PROCESS = "process"
    TENANT = "tenant"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AlertFeedback:
    feedback_id: int = 0
    alert_id: str = ""
    rule_id: str = ""
    verdict: str = AlertVerdict.TRUE_POSITIVE.value
    reason: str = ""
    analyst: str = ""
    role: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseComment:
    comment_id: int = 0
    case_id: str = ""
    author: str = ""
    role: str = ""
    body: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseEvidence:
    evidence_id: int = 0
    case_id: str = ""
    type: str = "alert"           # alert | event | ioc | file | url | note
    reference: str = ""           # alert_id, event_id, IOC value, ...
    description: str = ""
    added_by: str = ""
    timestamp: str = ""
    payload: Optional[dict[str, Any]] = None    # arbitrary supporting JSON

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    case_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = CaseSeverity.MEDIUM.value
    status: str = CaseStatus.NEW.value
    assignee: Optional[str] = None
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""
    closed_at: Optional[str] = None
    closure_reason: Optional[str] = None

    # SLA: due-by ISO timestamp computed at creation from severity
    sla_due_at: Optional[str] = None

    # Linked artefacts
    alert_ids: list[str] = field(default_factory=list)
    incident_ids: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Hydrated
    comments: list[CaseComment] = field(default_factory=list)
    evidence: list[CaseEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["comments"] = [c.to_dict() if isinstance(c, CaseComment) else c
                         for c in self.comments]
        d["evidence"] = [e.to_dict() if isinstance(e, CaseEvidence) else e
                         for e in self.evidence]
        return d


@dataclass
class Suppression:
    suppression_id: int = 0
    scope: str = SuppressionScope.RULE.value
    target: str = ""             # rule_id / username / host / ip / process_name
    reason: str = ""
    created_by: str = ""
    created_at: str = ""
    expires_at: str = ""         # MANDATORY iso timestamp
    active: bool = True
    approved_by: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# SLA defaults: hours-to-resolve per severity (SOC industry baselines)
# ---------------------------------------------------------------------------

SLA_HOURS = {
    CaseSeverity.CRITICAL.value: 1,
    CaseSeverity.HIGH.value: 4,
    CaseSeverity.MEDIUM.value: 24,
    CaseSeverity.LOW.value: 72,
}
