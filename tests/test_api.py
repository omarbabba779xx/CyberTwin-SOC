"""
Tests for the CyberTwin SOC FastAPI endpoints.
Uses httpx.AsyncClient + ASGITransport for in-process ASGI testing.
"""

import pytest
import pytest_asyncio
import httpx

from backend.api.main import app


@pytest_asyncio.fixture(scope="module")
async def client():
    """Async test client using ASGITransport – no running server needed."""
    # Trigger startup initialization (on_event startup doesn't fire in test mode)
    from backend.orchestrator import SimulationOrchestrator
    from backend.api.main import _orchestrator
    if not _orchestrator.attack_engine._scenarios:
        _orchestrator.initialise()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
class TestAPI:
    """Test API endpoints via ASGITransport (in-process)."""

    async def test_health_endpoint(self, client):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    async def test_get_environment(self, client, auth_headers):
        unauth = await client.get("/api/environment")
        assert unauth.status_code == 401

        resp = await client.get("/api/environment", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "network" in data or "hosts" in data

    async def test_get_hosts(self, client, auth_headers):
        unauth = await client.get("/api/environment/hosts")
        assert unauth.status_code == 401

        resp = await client.get("/api/environment/hosts", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    async def test_get_users(self, client, auth_headers):
        unauth = await client.get("/api/environment/users")
        assert unauth.status_code == 401

        resp = await client.get("/api/environment/users", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    async def test_get_scenarios(self, client):
        resp = await client.get("/api/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 4

    async def test_get_mitre_tactics(self, client):
        resp = await client.get("/api/mitre/tactics")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 14

    async def test_get_mitre_techniques(self, client):
        resp = await client.get("/api/mitre/techniques")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert len(data) > 0
        for tid, info in data.items():
            assert "name" in info
            assert "tactic" in info

    async def test_simulate_endpoint(self, client):
        from backend.auth import create_token
        token = create_token("analyst", "analyst")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get("/api/scenarios")
        scenarios = resp.json()
        sid = scenarios[0]["id"]
        oversized = await client.post("/api/simulate", json={
            "scenario_id": sid,
            "duration_minutes": 241,
            "normal_intensity": "low",
        }, headers=headers, timeout=300)
        assert oversized.status_code == 422

        resp = await client.post("/api/simulate", json={
            "scenario_id": sid,
            "duration_minutes": 15,
            "normal_intensity": "low",
        }, headers=headers, timeout=300)
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_score" in data
        assert "risk_level" in data
        assert "total_alerts" in data

    async def test_get_results_after_simulation(self, client):
        from backend.auth import create_token
        token = create_token("analyst", "analyst")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get("/api/scenarios")
        scenarios = resp.json()
        sid = scenarios[0]["id"]
        await client.post("/api/simulate", json={
            "scenario_id": sid,
            "duration_minutes": 15,
            "normal_intensity": "low",
        }, headers=headers, timeout=300)
        resp = await client.get(f"/api/results/{sid}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "logs" in data
        assert "alerts" in data
        assert "scores" in data

        unauth_history = await client.get("/api/history")
        assert unauth_history.status_code == 401

        oversized_history = await client.get("/api/history?limit=10000", headers=headers)
        assert oversized_history.status_code == 422

        history = await client.get("/api/history?limit=10", headers=headers)
        assert history.status_code == 200
        runs = history.json()
        assert isinstance(runs, list)
        assert runs

        run_id = runs[0]["id"]
        unauth_detail = await client.get(f"/api/history/{run_id}")
        assert unauth_detail.status_code == 401
        detail = await client.get(f"/api/history/{run_id}", headers=headers)
        assert detail.status_code == 200

        by_scenario = await client.get(f"/api/history/scenario/{sid}", headers=headers)
        assert by_scenario.status_code == 200
        assert isinstance(by_scenario.json(), list)

    async def test_threat_intel_endpoint(self, client):
        resp = await client.get("/api/threat-intel")
        assert resp.status_code == 200
        data = resp.json()
        assert "iocs" in data

    async def test_results_unknown_scenario_404(self, client):
        from backend.auth import create_token
        token = create_token("analyst", "analyst")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get("/api/results/nonexistent-scenario", headers=headers)
        assert resp.status_code == 404

    # ---- Auth endpoints ---------------------------------------------------

    async def test_login_valid_credentials(self, client):
        resp = await client.post("/api/auth/login", json={
            "username": "analyst",
            "password": "soc2024",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["username"] == "analyst"
        assert data["role"] == "analyst"
        assert data["expires_in"] == 3600

    async def test_login_invalid_credentials(self, client):
        resp = await client.post("/api/auth/login", json={
            "username": "analyst",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401

    async def test_get_me_with_token(self, client):
        login_resp = await client.post("/api/auth/login", json={
            "username": "admin",
            "password": "cybertwin2024",
        })
        token = login_resp.json()["token"]
        resp = await client.get("/api/auth/me", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    async def test_get_me_without_token(self, client):
        resp = await client.get("/api/auth/me")
        assert resp.status_code == 401
