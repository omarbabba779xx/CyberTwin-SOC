"""SQLAlchemy ORM models — production schema for CyberTwin SOC.

These models define the PostgreSQL-ready schema. Alembic generates and
applies migrations from these definitions.

Current tables:
  - simulation_runs    (replaces the SQLite table in backend/database.py)
  - security_events    (normalised events from the ingestion pipeline)
  - alerts             (detection engine output)
  - soc_cases          (SOC case management)
  - case_comments
  - case_evidence
  - alert_feedback
  - suppressions
  - audit_log

Design principles:
  - All tables include tenant_id for future multi-tenancy.
  - Indexes are defined alongside the columns they cover.
  - JSON columns use Text on SQLite, JSONB on PostgreSQL via TypeDecorator.
  - Timestamps are always stored in UTC.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean, DateTime, Float, Index, Integer, String, Text,
    TypeDecorator, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# JSON column — Text on SQLite, JSONB on PostgreSQL
# ---------------------------------------------------------------------------

class _JSONColumn(TypeDecorator):
    """Stores Python dicts/lists as JSON text on SQLite, delegates to JSONB on PG."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> str | None:
        if value is None:
            return None
        return json.dumps(value, default=str)

    def process_result_value(self, value: str | None, dialect) -> Any:
        if value is None:
            return None
        return json.loads(value)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(80), nullable=False)
    scenario_name: Mapped[str] = mapped_column(String(200), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    total_incidents: Mapped[int] = mapped_column(Integer, default=0)
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(40), default="unknown")
    summary_json: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_sim_runs_scenario", "scenario_id"),
        Index("ix_sim_runs_tenant_started", "tenant_id", "started_at"),
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    source_type: Mapped[str | None] = mapped_column(String(80))
    category: Mapped[str | None] = mapped_column(String(80))
    severity: Mapped[str | None] = mapped_column(String(20))
    user_name: Mapped[str | None] = mapped_column(String(200))
    host_name: Mapped[str | None] = mapped_column(String(200))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    process_name: Mapped[str | None] = mapped_column(String(200))
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_events_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_events_source_type", "source_type"),
        Index("ix_events_user_host", "user_name", "host_name"),
        Index("ix_events_src_dst_ip", "src_ip", "dst_ip"),
        Index("ix_events_process", "process_name"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    rule_id: Mapped[str | None] = mapped_column(String(80))
    technique_id: Mapped[str | None] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")
    title: Mapped[str | None] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_rule_technique", "rule_id", "technique_id"),
    )


class SocCase(Base):
    __tablename__ = "soc_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(120))
    closure_reason: Mapped[str | None] = mapped_column(Text)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags_json: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_cases_tenant_status", "tenant_id", "status"),
        Index("ix_cases_assignee_status", "assignee", "status"),
        Index("ix_cases_sla_due", "sla_due_at"),
    )


class CaseComment(Base):
    __tablename__ = "case_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    case_id: Mapped[str] = mapped_column(String(80), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    author: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str | None] = mapped_column(String(40))
    body: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("ix_comments_case_id", "case_id"),
    )


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    case_id: Mapped[str] = mapped_column(String(80), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    added_by: Mapped[str] = mapped_column(String(120), nullable=False)
    type: Mapped[str] = mapped_column(String(40), default="alert")
    reference: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_evidence_case_id", "case_id"),
    )


class AlertFeedback(Base):
    __tablename__ = "alert_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feedback_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    alert_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    analyst: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str | None] = mapped_column(String(40))
    verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_feedback_alert_id", "alert_id"),
        Index("ix_feedback_rule_id", "rule_id"),
        Index("ix_feedback_tenant", "tenant_id"),
    )


class Suppression(Base):
    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(120))
    scope: Mapped[str] = mapped_column(String(40), nullable=False)
    target: Mapped[str] = mapped_column(String(250), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (
        Index("ix_suppressions_scope_active", "scope", "active"),
        Index("ix_suppressions_tenant", "tenant_id"),
    )


class AuditLog(Base):
    __tablename__ = "audit_log_v2"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        server_default=func.now())
    tenant_id: Mapped[str] = mapped_column(String(80), nullable=False, default="default")
    username: Mapped[str | None] = mapped_column(String(120))
    role: Mapped[str | None] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(200))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(String(20), default="success")
    details: Mapped[str | None] = mapped_column(_JSONColumn)

    __table_args__ = (
        Index("ix_audit_tenant_ts", "tenant_id", "timestamp"),
        Index("ix_audit_actor_action", "username", "action"),
    )
