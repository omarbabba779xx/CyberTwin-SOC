"""Phase 5 tests: granular RBAC, observability, connectors."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Granular RBAC (backward compatibility + new roles)
# ---------------------------------------------------------------------------

class TestGranularRBAC:

    def test_legacy_roles_still_have_legacy_permissions(self):
        from backend.auth import has_permission
        # Legacy permission names continue to work for legacy roles.
        assert has_permission("admin",   "configure_system")
        assert has_permission("analyst", "run_simulation")
        assert has_permission("viewer",  "view_results")
        # Plus the scoped ones, on the right roles.
        assert has_permission("admin",   "case:close")
        assert has_permission("analyst", "case:write")
        assert not has_permission("viewer", "case:write")

    def test_new_role_platform_admin_has_everything(self):
        from backend.auth import has_permission, PERMISSIONS_SCOPED, PERMISSIONS_LEGACY
        for p in PERMISSIONS_SCOPED | PERMISSIONS_LEGACY:
            assert has_permission("platform_admin", p), f"missing perm {p}"

    def test_detection_engineer_can_create_rules(self):
        from backend.auth import has_permission
        assert has_permission("detection_engineer", "rule:create")
        assert has_permission("detection_engineer", "rule:approve")
        assert has_permission("detection_engineer", "rule:deploy")
        assert not has_permission("detection_engineer", "case:close")

    def test_tier1_analyst_cannot_close_cases(self):
        from backend.auth import has_permission
        assert has_permission("tier1_analyst", "case:read")
        assert has_permission("tier1_analyst", "case:write")
        assert not has_permission("tier1_analyst", "case:close")
        assert not has_permission("tier1_analyst", "rule:approve")

    def test_auditor_is_read_only(self):
        from backend.auth import has_permission
        assert has_permission("auditor", "audit:read")
        assert has_permission("auditor", "case:read")
        # No write permission anywhere
        for p in ("case:write", "case:close", "rule:create",
                  "rule:approve", "ingestion:write", "configure_system"):
            assert not has_permission("auditor", p), f"auditor must not have {p}"

    def test_service_account_can_only_ingest(self):
        from backend.auth import has_permission
        assert has_permission("service_account", "ingestion:write")
        assert has_permission("service_account", "rule:read")
        assert not has_permission("service_account", "case:write")

    def test_unknown_role_no_perms(self):
        from backend.auth import has_permission
        assert not has_permission("unknown_role", "case:read")


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

class TestObservability:

    def test_metrics_endpoint_returns_prometheus_format(self, client, auth_headers):
        # Generate at least one sample request first
        client.get("/api/health")
        r = client.get("/api/metrics", headers=auth_headers)
        # Endpoint is rate-limited but unauthenticated - works anyway
        assert r.status_code == 200
        body = r.text
        # Required Prometheus metric names must be present
        assert "cybertwin_api_request_duration_seconds" in body
        assert "cybertwin_events_ingested_total" in body
        assert "# TYPE" in body or "# HELP" in body

    def test_request_id_header_round_trip(self, client):
        # Without an incoming X-Request-ID, the server must generate one.
        r = client.get("/api/health")
        assert "x-request-id" in {k.lower() for k in r.headers.keys()}

    def test_request_id_preserved_when_provided(self, client):
        rid = "trace-1234567890abcdef"
        r = client.get("/api/health", headers={"X-Request-ID": rid})
        assert r.headers.get("X-Request-ID") == rid

    def test_health_deep_returns_dependency_status(self, client):
        r = client.get("/api/health/deep")
        assert r.status_code in (200, 503)
        body = r.json()
        assert "checks" in body
        assert "cache" in body["checks"]
        assert "database" in body["checks"]
        assert "ingestion" in body["checks"]


# ---------------------------------------------------------------------------
# Enterprise connectors
# ---------------------------------------------------------------------------

class TestConnectors:

    def test_registry_contains_mocks_and_stubs(self):
        from backend.connectors import list_connectors
        names = {(c["kind"], c["name"]) for c in list_connectors()}
        # Every kind has a mock
        for kind in ("siem", "soar", "edr", "itsm", "ti"):
            assert (kind, "mock") in names, f"no mock for {kind}"
        # Stubs are registered
        for stub in (("siem", "splunk"), ("siem", "sentinel"),
                     ("soar", "thehive"), ("itsm", "jira"), ("ti", "misp")):
            assert stub in names

    def test_mock_connectors_actually_work(self):
        from backend.connectors import get_connector
        for kind in ("siem", "soar", "edr", "itsm", "ti"):
            res = get_connector(kind, "mock").check_connection()
            assert res.success is True
            assert "ready" in res.message

    def test_mock_soar_creates_case(self):
        from backend.connectors import get_connector
        out = get_connector("soar", "mock").create_case(
            title="Test", description="d", severity="high",
        )
        assert out.success is True
        assert out.data["case_id"].startswith("MOCK-CASE-")

    def test_mock_ti_lookup_is_deterministic(self):
        from backend.connectors import get_connector
        ti = get_connector("ti", "mock")
        # 'evil' substring -> malicious; otherwise clean.
        bad = ti.lookup("c2.evil.com")
        good = ti.lookup("legit.example.com")
        assert bad.data["malicious"] is True
        assert good.data["malicious"] is False

    def test_stub_raises_not_implemented(self):
        from backend.connectors import get_connector
        # `splunk` and `thehive` are now production-grade implementations
        # (see backend/connectors/splunk.py + thehive.py). The remaining
        # stubs cover sentinel/elastic/jira/servicenow/misp/opencti.
        with pytest.raises(NotImplementedError):
            get_connector("siem", "sentinel").check_connection()

    def test_unknown_connector_raises(self):
        from backend.connectors import get_connector
        from backend.connectors.base import ConnectorError
        with pytest.raises(ConnectorError):
            get_connector("siem", "definitely-not-real")


# ---------------------------------------------------------------------------
# Connector API endpoints
# ---------------------------------------------------------------------------

class TestConnectorAPI:

    def test_list_endpoint(self, client, auth_headers):
        r = client.get("/api/connectors", headers=auth_headers)
        assert r.status_code == 200
        connectors = r.json()["connectors"]
        # All 5 mock kinds are advertised as implemented
        mocks = [c for c in connectors if c["name"] == "mock" and c["implemented"]]
        assert len(mocks) >= 5

    def test_check_mock_endpoint(self, client, auth_headers):
        r = client.get("/api/connectors/siem/mock/check", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is True

    def test_check_stub_returns_501(self, client, auth_headers):
        # sentinel is still a stub; splunk is now production-grade.
        r = client.get("/api/connectors/siem/sentinel/check", headers=auth_headers)
        assert r.status_code == 501

    def test_check_unknown_returns_404(self, client, auth_headers):
        r = client.get("/api/connectors/siem/no-such/check", headers=auth_headers)
        assert r.status_code == 404
