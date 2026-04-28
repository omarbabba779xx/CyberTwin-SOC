"""Integration tests for runtime multi-tenant isolation.

Verifies:
- TenantScopeMiddleware extracts tenant_id from JWT
- TenantScopeMiddleware falls back to "default" without auth
- TenantRepository filters all queries by tenant_id automatically
- Tenant A cannot read Tenant B's records via TenantRepository
- create_token() embeds tenant_id in JWT payload
- The tenant_id from JWT propagates through to request.state
"""
from __future__ import annotations

from datetime import datetime, timezone

import jwt
import pytest


# ---------------------------------------------------------------------------
# JWT-side: tenant_id is embedded in the access token
# ---------------------------------------------------------------------------

class TestJWTTenantClaim:
    def test_create_token_embeds_tenant_id(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM
        token = create_token("alice", "analyst", tenant_id="tenant-acme")
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert decoded["tenant_id"] == "tenant-acme"
        assert decoded["sub"] == "alice"

    def test_default_tenant_when_omitted(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM
        token = create_token("alice", "analyst")
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert decoded["tenant_id"] == "default"

    def test_refresh_token_carries_tenant_id(self):
        from backend.auth import create_refresh_token, JWT_SECRET, JWT_ALGORITHM
        token = create_refresh_token("alice", "analyst", tenant_id="tenant-acme")
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert decoded["tenant_id"] == "tenant-acme"
        assert decoded["type"] == "refresh"


# ---------------------------------------------------------------------------
# Middleware-side: TenantScopeMiddleware reads tenant_id from JWT into request.state
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_app():
    """Minimal FastAPI app wired only with the TenantScopeMiddleware.

    We use a Starlette ``Route`` instead of a FastAPI path operation so the
    parameter annotation is unambiguous (FastAPI's path-operation inspector
    treats ``request: Request`` as a query parameter under some import
    orderings)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.requests import Request as StarletteRequest
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from backend.middleware.tenant import TenantScopeMiddleware

    async def whoami(request: StarletteRequest):
        return JSONResponse({"tenant_id": request.state.tenant_id})

    app = FastAPI()
    app.add_middleware(TenantScopeMiddleware)
    app.router.routes.append(Route("/whoami", whoami, methods=["GET"]))

    return TestClient(app)


class TestTenantMiddleware:
    def test_no_auth_uses_default_tenant(self, tenant_app):
        resp = tenant_app.get("/whoami")
        assert resp.status_code == 200, f"body={resp.text}"
        assert resp.json()["tenant_id"] == "default"

    def test_jwt_with_tenant_propagates(self, tenant_app):
        from backend.auth import create_token
        token = create_token("alice", "analyst", tenant_id="tenant-acme")
        resp = tenant_app.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == "tenant-acme"

    def test_invalid_jwt_falls_back_to_default(self, tenant_app):
        resp = tenant_app.get(
            "/whoami", headers={"Authorization": "Bearer this.is.not.a.jwt"}
        )
        assert resp.status_code == 200
        assert resp.json()["tenant_id"] == "default"

    def test_expired_jwt_falls_back_to_default(self, tenant_app):
        """An expired JWT must not crash the middleware — fall back to default."""
        from backend.auth import JWT_SECRET, JWT_ALGORITHM
        past = datetime.now(timezone.utc).replace(year=2020)
        expired = jwt.encode(
            {"sub": "alice", "tenant_id": "tenant-acme", "exp": past},
            JWT_SECRET,
            algorithm=JWT_ALGORITHM,
        )
        resp = tenant_app.get(
            "/whoami", headers={"Authorization": f"Bearer {expired}"}
        )
        assert resp.status_code == 200
        # Even though the JWT was decoded, expiry makes us fall back to default
        assert resp.json()["tenant_id"] == "default"

    def test_three_distinct_tenants_isolated_in_state(self, tenant_app):
        """Sequential requests with distinct tokens must yield distinct tenant_ids."""
        from backend.auth import create_token

        for tenant in ["tenantA", "tenantB", "tenantC"]:
            token = create_token("user", "analyst", tenant_id=tenant)
            resp = tenant_app.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )
            assert resp.json()["tenant_id"] == tenant


# ---------------------------------------------------------------------------
# Repository-side: TenantRepository auto-filters every query by tenant_id
# ---------------------------------------------------------------------------

@pytest.fixture
def in_memory_db(monkeypatch):
    """Build an in-memory SQLite DB with a tenant-scoped model for testing."""
    from sqlalchemy import create_engine, Column, Integer, String
    from sqlalchemy.orm import declarative_base, sessionmaker

    Base = declarative_base()

    class Widget(Base):
        __tablename__ = "widgets"
        id = Column(Integer, primary_key=True)
        tenant_id = Column(String(80), nullable=False, index=True)
        name = Column(String(120))

    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session, Widget


class TestTenantRepository:
    def test_query_filters_by_tenant(self, in_memory_db):
        Session, Widget = in_memory_db
        from backend.db.repository import TenantRepository

        sess = Session()
        sess.add_all([
            Widget(tenant_id="tenantA", name="a-1"),
            Widget(tenant_id="tenantA", name="a-2"),
            Widget(tenant_id="tenantB", name="b-1"),
        ])
        sess.commit()

        repo_a = TenantRepository(sess, tenant_id="tenantA")
        repo_b = TenantRepository(sess, tenant_id="tenantB")

        list_a = repo_a.list_all(Widget)
        list_b = repo_b.list_all(Widget)

        assert {w.name for w in list_a} == {"a-1", "a-2"}
        assert {w.name for w in list_b} == {"b-1"}

    def test_get_by_id_blocks_cross_tenant_read(self, in_memory_db):
        """Tenant A must not be able to read tenant B's record by guessing the id."""
        Session, Widget = in_memory_db
        from backend.db.repository import TenantRepository

        sess = Session()
        b_widget = Widget(tenant_id="tenantB", name="secret-b")
        sess.add(b_widget)
        sess.commit()
        b_id = b_widget.id

        repo_a = TenantRepository(sess, tenant_id="tenantA")
        result = repo_a.get_by_id(Widget, b_id)
        assert result is None  # Tenant A cannot see tenant B's row

    def test_count_is_per_tenant(self, in_memory_db):
        Session, Widget = in_memory_db
        from backend.db.repository import TenantRepository

        sess = Session()
        for i in range(5):
            sess.add(Widget(tenant_id="tenantA", name=f"a-{i}"))
        for i in range(3):
            sess.add(Widget(tenant_id="tenantB", name=f"b-{i}"))
        sess.commit()

        assert TenantRepository(sess, "tenantA").count(Widget) == 5
        assert TenantRepository(sess, "tenantB").count(Widget) == 3

    def test_add_stamps_tenant_id_automatically(self, in_memory_db):
        """add() must overwrite any tenant_id passed in instance to prevent spoofing."""
        Session, Widget = in_memory_db
        from backend.db.repository import TenantRepository

        sess = Session()
        repo = TenantRepository(sess, tenant_id="tenantA")

        # Caller tries to spoof tenant_id by setting it directly
        spoofed = Widget(tenant_id="tenantB", name="spoof")
        repo.add(spoofed)
        sess.commit()

        # The stored row must have the repo's tenant_id, not the spoofed value
        stored = sess.query(Widget).filter_by(name="spoof").first()
        assert stored.tenant_id == "tenantA"
