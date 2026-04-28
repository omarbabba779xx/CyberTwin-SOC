"""Dynamic RBAC store — tenant-specific role definitions stored in database.

Falls back to the static ROLES dict in backend.auth when no custom
roles are defined for a tenant.
"""

from __future__ import annotations

import logging
from typing import Sequence

from sqlalchemy.orm import Session

from backend.auth import ROLES
from backend.db.models import TenantRole

logger = logging.getLogger("cybertwin.rbac_store")


def get_permissions(session: Session, tenant_id: str, role: str) -> set[str]:
    """Return permission set for *role* within *tenant_id*.

    Checks the database first for a tenant-specific override; falls back
    to the static ROLES dict when no custom definition exists.
    """
    row = (
        session.query(TenantRole)
        .filter(TenantRole.tenant_id == tenant_id, TenantRole.role_name == role)
        .first()
    )
    if row is not None and row.permissions_json is not None:
        return set(row.permissions_json)

    static = ROLES.get(role)
    if static is not None:
        return set(static)

    return set()


def set_tenant_role(
    session: Session,
    tenant_id: str,
    role_name: str,
    permissions: list[str],
) -> TenantRole:
    """Create or update a custom role for *tenant_id*.

    Returns the persisted ``TenantRole`` instance.
    """
    row = (
        session.query(TenantRole)
        .filter(TenantRole.tenant_id == tenant_id, TenantRole.role_name == role_name)
        .first()
    )
    if row is None:
        row = TenantRole(
            tenant_id=tenant_id,
            role_name=role_name,
            permissions_json=permissions,
        )
        session.add(row)
        logger.info("Created custom role %r for tenant %s", role_name, tenant_id)
    else:
        row.permissions_json = permissions
        logger.info("Updated custom role %r for tenant %s", role_name, tenant_id)

    session.flush()
    return row


def list_tenant_roles(session: Session, tenant_id: str) -> Sequence[TenantRole]:
    """Return all custom roles defined for *tenant_id*."""
    return (
        session.query(TenantRole)
        .filter(TenantRole.tenant_id == tenant_id)
        .order_by(TenantRole.role_name)
        .all()
    )


def delete_tenant_role(session: Session, tenant_id: str, role_name: str) -> bool:
    """Delete a custom role for *tenant_id*.

    Returns True if a row was deleted, False if no matching role existed.
    """
    count = (
        session.query(TenantRole)
        .filter(TenantRole.tenant_id == tenant_id, TenantRole.role_name == role_name)
        .delete()
    )
    if count:
        session.flush()
        logger.info("Deleted custom role %r for tenant %s", role_name, tenant_id)
    return count > 0
