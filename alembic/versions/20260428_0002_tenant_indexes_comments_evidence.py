"""Add tenant_id composite indexes on case_comments and case_evidence

Closes the multi-tenancy structural test gap: every tenant_id column must
be reachable via at least one index, otherwise listing a tenant's data
forces a full-table scan.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_comments_tenant_case",
        "case_comments",
        ["tenant_id", "case_id"],
        unique=False,
    )
    op.create_index(
        "ix_evidence_tenant_case",
        "case_evidence",
        ["tenant_id", "case_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_tenant_case", table_name="case_evidence")
    op.drop_index("ix_comments_tenant_case", table_name="case_comments")
