"""Add tenant_roles table for dynamic per-tenant RBAC

Stores custom role definitions per tenant. Each tenant can override
or extend the static ROLES dict with their own permission sets.

Revision ID: 0005
Revises: 0002
Create Date: 2026-04-28
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0005"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_roles",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.String(80), nullable=False),
        sa.Column("role_name", sa.String(80), nullable=False),
        sa.Column("permissions_json", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index(
        "ix_tenant_roles_tenant_role",
        "tenant_roles",
        ["tenant_id", "role_name"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_tenant_roles_tenant_role", table_name="tenant_roles")
    op.drop_table("tenant_roles")
