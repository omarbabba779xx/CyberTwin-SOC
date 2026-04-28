"""Base repository with automatic tenant_id filtering for all queries."""

from __future__ import annotations

from typing import Any, TypeVar

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from backend.db.session import get_db

T = TypeVar("T")


class TenantRepository:
    """Wraps a SQLAlchemy session and scopes all operations to a single tenant."""

    def __init__(self, session: Session, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id

    def query(self, model: type[T]):
        """Return a query pre-filtered to the current tenant."""
        return self.session.query(model).filter(model.tenant_id == self.tenant_id)  # type: ignore[attr-defined]

    def add(self, instance: Any) -> None:
        """Set tenant_id on the instance and add it to the session."""
        instance.tenant_id = self.tenant_id
        self.session.add(instance)

    def get_by_id(self, model: type[T], id: Any) -> T | None:
        """Fetch a single record by primary key, scoped to the current tenant."""
        return (
            self.session.query(model)
            .filter(model.tenant_id == self.tenant_id, model.id == id)  # type: ignore[attr-defined]
            .first()
        )

    def list_all(self, model: type[T], limit: int = 100, offset: int = 0) -> list[T]:
        """Paginated listing scoped to the current tenant."""
        return (
            self.session.query(model)
            .filter(model.tenant_id == self.tenant_id)  # type: ignore[attr-defined]
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count(self, model: type[T]) -> int:
        """Count records for the current tenant."""
        return (
            self.session.query(model)
            .filter(model.tenant_id == self.tenant_id)  # type: ignore[attr-defined]
            .count()
        )


def get_tenant_repo(
    request: Request,
    session: Session = Depends(get_db),
) -> TenantRepository:
    """FastAPI dependency — creates a TenantRepository from the current request's tenant_id."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    return TenantRepository(session=session, tenant_id=tenant_id)
