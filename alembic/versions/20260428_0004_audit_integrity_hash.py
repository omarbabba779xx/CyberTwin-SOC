"""Add integrity_hash column to audit_log_v2

Tamper-evident audit trail (Phase 3.1): each audit entry carries a SHA-256
hash chained to its predecessor, enabling forensic verification that no
record has been inserted, deleted, or modified after the fact.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_log_v2",
        sa.Column("integrity_hash", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_log_v2", "integrity_hash")
