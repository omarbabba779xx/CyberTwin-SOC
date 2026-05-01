"""Complete SOC runtime columns for PostgreSQL CRUD.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-01
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("soc_cases", sa.Column("closed_at", sa.DateTime(timezone=True)))
    op.add_column("soc_cases", sa.Column("alert_ids_json", sa.Text))
    op.add_column("soc_cases", sa.Column("incident_ids_json", sa.Text))
    op.add_column("soc_cases", sa.Column("affected_hosts_json", sa.Text))
    op.add_column("soc_cases", sa.Column("affected_users_json", sa.Text))
    op.add_column("soc_cases", sa.Column("mitre_techniques_json", sa.Text))


def downgrade() -> None:
    op.drop_column("soc_cases", "mitre_techniques_json")
    op.drop_column("soc_cases", "affected_users_json")
    op.drop_column("soc_cases", "affected_hosts_json")
    op.drop_column("soc_cases", "incident_ids_json")
    op.drop_column("soc_cases", "alert_ids_json")
    op.drop_column("soc_cases", "closed_at")
