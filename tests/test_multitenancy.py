"""Multi-tenancy structural guards.

These tests do NOT verify runtime tenant isolation (that requires the
repository pattern + active tenant filters, planned for v3.2). They DO
guard against accidentally adding a new ORM model without `tenant_id`,
which is the prerequisite for any future row-level isolation.

If a new ORM model is genuinely tenant-agnostic (e.g. a global lookup
table), add it to `EXEMPT_TABLES` with a comment explaining why.
"""
from __future__ import annotations

import pytest


# Tables that legitimately have no tenant_id.
# Document the reason on every entry — reviewers must justify adding more.
EXEMPT_TABLES: dict[str, str] = {
    # No exemptions today. Every cybertwin domain row is per-tenant.
}


def _all_orm_tables():
    from backend.db.models import Base
    return Base.metadata.tables


class TestTenantIdPresence:
    """Every ORM model must carry tenant_id (or be explicitly exempt)."""

    def test_all_models_have_tenant_id(self):
        tables = _all_orm_tables()
        assert tables, "No ORM tables registered — backend.db.models import failed?"

        missing = []
        for name, table in tables.items():
            if name in EXEMPT_TABLES:
                continue
            if "tenant_id" not in table.columns:
                missing.append(name)

        assert not missing, (
            f"ORM tables missing tenant_id (and not in EXEMPT_TABLES): {missing}. "
            f"Either add a tenant_id column or document the exemption in "
            f"tests/test_multitenancy.py::EXEMPT_TABLES."
        )

    def test_tenant_id_indexed_for_query_paths(self):
        """Every tenant_id column must be reachable via at least one index.

        Without an index, listing a tenant's data forces a full-table scan.
        Composite indexes count (e.g. ix_alerts_tenant_created).
        """
        tables = _all_orm_tables()
        unindexed = []
        for name, table in tables.items():
            if name in EXEMPT_TABLES:
                continue
            if "tenant_id" not in table.columns:
                continue
            covered = any(
                "tenant_id" in [c.name for c in idx.columns]
                for idx in table.indexes
            )
            if not covered:
                unindexed.append(name)

        assert not unindexed, (
            f"Tables with tenant_id but no covering index: {unindexed}. "
            f"Add a composite index (e.g. Index('ix_<table>_tenant_<col>', "
            f"'tenant_id', '<query_col>'))."
        )


class TestExemptionList:
    """Exemptions must be deliberate, not accidental."""

    def test_exemptions_are_real_tables(self):
        tables = _all_orm_tables()
        ghost = [t for t in EXEMPT_TABLES if t not in tables]
        assert not ghost, (
            f"EXEMPT_TABLES references non-existent tables: {ghost}. "
            f"Remove the stale entry."
        )


class TestRoleCatalog:
    """RBAC permissions referenced by tests must exist in the role catalog.

    Drift between tests/decorators and the role catalog is the #1 source
    of '403 in production after green CI' bugs.
    """

    def test_analyst_can_complete_full_case_lifecycle(self):
        from backend.auth import ROLES
        analyst_perms = ROLES["analyst"]
        required = {
            "case:read", "case:write", "case:assign", "case:close",
            "feedback:write",
        }
        missing = required - analyst_perms
        assert not missing, (
            f"Analyst role is missing case-lifecycle permissions: {missing}. "
            f"Update backend/auth.py::ROLES['analyst']."
        )

    def test_no_role_has_undefined_permissions(self):
        from backend.auth import ROLES, _all_perms
        catalog = _all_perms()
        for role, perms in ROLES.items():
            extras = perms - catalog
            assert not extras, (
                f"Role '{role}' references permissions not in the catalog: "
                f"{extras}. Either add them to PERMISSIONS_SCOPED or fix the "
                f"role definition."
            )
