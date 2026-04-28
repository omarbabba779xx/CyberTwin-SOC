"""Add foreign-key constraints between case/evidence/feedback tables.

- case_comments.case_id  → soc_cases.case_id   ON DELETE CASCADE
- case_evidence.case_id  → soc_cases.case_id   ON DELETE CASCADE
- alert_feedback.alert_id → alerts.alert_id     ON DELETE SET NULL

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_foreign_key(
        "fk_case_comments_case_id",
        "case_comments",
        "soc_cases",
        ["case_id"],
        ["case_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_case_evidence_case_id",
        "case_evidence",
        "soc_cases",
        ["case_id"],
        ["case_id"],
        ondelete="CASCADE",
    )

    # alert_feedback.alert_id was NOT NULL — relax so SET NULL can work.
    op.alter_column(
        "alert_feedback",
        "alert_id",
        existing_type=sa.String(80),
        nullable=True,
    )
    op.create_foreign_key(
        "fk_alert_feedback_alert_id",
        "alert_feedback",
        "alerts",
        ["alert_id"],
        ["alert_id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_alert_feedback_alert_id", "alert_feedback", type_="foreignkey")
    op.alter_column(
        "alert_feedback",
        "alert_id",
        existing_type=sa.String(80),
        nullable=False,
    )
    op.drop_constraint("fk_case_evidence_case_id", "case_evidence", type_="foreignkey")
    op.drop_constraint("fk_case_comments_case_id", "case_comments", type_="foreignkey")
