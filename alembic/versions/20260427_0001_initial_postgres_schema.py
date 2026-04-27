"""Initial PostgreSQL schema — all production tables.

Revision ID: 0001
Revises:
Create Date: 2026-04-27 00:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "simulation_runs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("run_id", sa.String(80), unique=True, nullable=False),
        sa.Column("scenario_id", sa.String(80), nullable=False),
        sa.Column("scenario_name", sa.String(200), nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("total_events", sa.Integer, server_default="0"),
        sa.Column("total_alerts", sa.Integer, server_default="0"),
        sa.Column("total_incidents", sa.Integer, server_default="0"),
        sa.Column("overall_score", sa.Float, server_default="0.0"),
        sa.Column("risk_level", sa.String(40), server_default="unknown"),
        sa.Column("summary_json", sa.Text),
    )
    op.create_index("ix_sim_runs_scenario", "simulation_runs", ["scenario_id"])
    op.create_index("ix_sim_runs_tenant_started", "simulation_runs", ["tenant_id", "started_at"])

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("event_id", sa.String(80), unique=True, nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("source_type", sa.String(80)),
        sa.Column("category", sa.String(80)),
        sa.Column("severity", sa.String(20)),
        sa.Column("user_name", sa.String(200)),
        sa.Column("host_name", sa.String(200)),
        sa.Column("src_ip", sa.String(45)),
        sa.Column("dst_ip", sa.String(45)),
        sa.Column("process_name", sa.String(200)),
        sa.Column("is_malicious", sa.Boolean, server_default="false"),
        sa.Column("payload", sa.Text),
    )
    op.create_index("ix_events_tenant_ts", "security_events", ["tenant_id", "timestamp"])
    op.create_index("ix_events_source_type", "security_events", ["source_type"])
    op.create_index("ix_events_user_host", "security_events", ["user_name", "host_name"])
    op.create_index("ix_events_src_dst_ip", "security_events", ["src_ip", "dst_ip"])
    op.create_index("ix_events_process", "security_events", ["process_name"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("alert_id", sa.String(80), unique=True, nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("rule_id", sa.String(80)),
        sa.Column("technique_id", sa.String(20)),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("status", sa.String(20), server_default="open"),
        sa.Column("title", sa.String(500)),
        sa.Column("description", sa.Text),
        sa.Column("payload", sa.Text),
    )
    op.create_index("ix_alerts_tenant_created", "alerts", ["tenant_id", "created_at"])
    op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])
    op.create_index("ix_alerts_rule_technique", "alerts", ["rule_id", "technique_id"])

    op.create_table(
        "soc_cases",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("case_id", sa.String(80), unique=True, nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("severity", sa.String(20), server_default="medium"),
        sa.Column("status", sa.String(20), server_default="open"),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("assignee", sa.String(120)),
        sa.Column("closure_reason", sa.Text),
        sa.Column("sla_due_at", sa.DateTime(timezone=True)),
        sa.Column("tags_json", sa.Text),
    )
    op.create_index("ix_cases_tenant_status", "soc_cases", ["tenant_id", "status"])
    op.create_index("ix_cases_assignee_status", "soc_cases", ["assignee", "status"])
    op.create_index("ix_cases_sla_due", "soc_cases", ["sla_due_at"])

    op.create_table(
        "case_comments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("comment_id", sa.String(80), unique=True, nullable=False),
        sa.Column("case_id", sa.String(80), nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("author", sa.String(120), nullable=False),
        sa.Column("role", sa.String(40)),
        sa.Column("body", sa.Text, nullable=False),
    )
    op.create_index("ix_comments_case_id", "case_comments", ["case_id"])

    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("evidence_id", sa.String(80), unique=True, nullable=False),
        sa.Column("case_id", sa.String(80), nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("added_by", sa.String(120), nullable=False),
        sa.Column("type", sa.String(40), server_default="alert"),
        sa.Column("reference", sa.String(500), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("payload", sa.Text),
    )
    op.create_index("ix_evidence_case_id", "case_evidence", ["case_id"])

    op.create_table(
        "alert_feedback",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("feedback_id", sa.String(80), unique=True, nullable=False),
        sa.Column("alert_id", sa.String(80), nullable=False),
        sa.Column("rule_id", sa.String(120), nullable=False),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("analyst", sa.String(120), nullable=False),
        sa.Column("role", sa.String(40)),
        sa.Column("verdict", sa.String(40), nullable=False),
        sa.Column("reason", sa.Text),
    )
    op.create_index("ix_feedback_alert_id", "alert_feedback", ["alert_id"])
    op.create_index("ix_feedback_rule_id", "alert_feedback", ["rule_id"])
    op.create_index("ix_feedback_tenant", "alert_feedback", ["tenant_id"])

    op.create_table(
        "suppressions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("approved_by", sa.String(120)),
        sa.Column("scope", sa.String(40), nullable=False),
        sa.Column("target", sa.String(250), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("expires_at", sa.String(80)),
        sa.Column("active", sa.Boolean, server_default="true"),
    )
    op.create_index("ix_suppressions_scope_active", "suppressions", ["scope", "active"])
    op.create_index("ix_suppressions_tenant", "suppressions", ["tenant_id"])

    op.create_table(
        "audit_log_v2",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(80), nullable=False, server_default="default"),
        sa.Column("username", sa.String(120)),
        sa.Column("role", sa.String(40)),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("resource", sa.String(200)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("status", sa.String(20), server_default="success"),
        sa.Column("details", sa.Text),
    )
    op.create_index("ix_audit_tenant_ts", "audit_log_v2", ["tenant_id", "timestamp"])
    op.create_index("ix_audit_actor_action", "audit_log_v2", ["username", "action"])


def downgrade() -> None:
    op.drop_table("audit_log_v2")
    op.drop_table("suppressions")
    op.drop_table("alert_feedback")
    op.drop_table("case_evidence")
    op.drop_table("case_comments")
    op.drop_table("soc_cases")
    op.drop_table("alerts")
    op.drop_table("security_events")
    op.drop_table("simulation_runs")
