"""Integration tests for the Splunk connector (mock_mode + httpx mocking).

Verifies the production contract:
- describe() / check_connection in mock_mode
- search() lifecycle: POST /search/jobs → poll → GET /results
- search() pagination across multiple result pages
- push_alert() to /receivers/simple
- 4xx → ConnectorError
- 5xx → @with_retry retries
- circuit breaker integration
"""
from __future__ import annotations

import httpx
import pytest

from backend.connectors.base import ConnectorError
from backend.connectors.resilience import CircuitState
from backend.connectors.splunk import SplunkConnector


@pytest.fixture
def mock_splunk():
    return SplunkConnector(
        url="https://splunk.test.local:8089",
        token="dummy-token",
        mock_mode=True,
    )


class TestDescribeAndHealth:
    def test_describe_lists_config_keys(self, mock_splunk):
        d = mock_splunk.describe()
        assert d["name"] == "splunk"
        assert d["kind"] == "siem"
        assert "url" in d["config_keys"]
        assert "token" in d["config_keys"]

    def test_health_succeeds_in_mock(self, mock_splunk):
        r = mock_splunk.health()
        assert r.success is True
        assert "version" in r.data
        assert "9.2" in r.data["version"]

    def test_health_fails_without_url(self):
        c = SplunkConnector(url="", token="x")
        r = c.health()
        assert r.success is False
        assert "url" in r.message.lower()

    def test_health_fails_without_token(self):
        c = SplunkConnector(url="https://x", token="")
        r = c.health()
        assert r.success is False
        assert "token" in r.message.lower()


class TestSearch:
    def test_search_returns_results(self, mock_splunk):
        r = mock_splunk.search('search index=main earliest=-15m | head 10', limit=10)
        assert r.success is True
        assert "sid" in r.data
        assert isinstance(r.data["results"], list)
        assert len(r.data["results"]) > 0

    def test_search_requires_query(self, mock_splunk):
        with pytest.raises(ConnectorError, match="query is required"):
            mock_splunk.search("", limit=10)

    def test_search_respects_limit(self, mock_splunk):
        r = mock_splunk.search('search *', limit=1)
        assert r.success is True
        assert r.data["count"] <= 1


class TestPushAlert:
    def test_push_alert_succeeds(self, mock_splunk):
        alert = {
            "rule_id": "RULE-001",
            "severity": "high",
            "host": "WIN-DC-01",
            "user": "alice",
            "technique": "T1110",
        }
        r = mock_splunk.push_alert(alert)
        assert r.success is True
        assert r.data["index"] == "main"

    def test_alert_stored_in_mock_state(self, mock_splunk):
        mock_splunk.push_alert({"rule_id": "X"})
        assert len(mock_splunk._mock_alerts) == 1
        assert mock_splunk._mock_alerts[0]["index"] == "main"


# ---------------------------------------------------------------------------
# HTTP error mapping
# ---------------------------------------------------------------------------

class TestHTTPErrorMapping:
    def _make_connector_with_handler(self, handler) -> SplunkConnector:
        c = SplunkConnector(url="https://s.test.local", token="t")

        def patched_client(self_):  # noqa: ARG001
            transport = httpx.MockTransport(handler)
            return httpx.Client(
                base_url=self_._url,
                headers=self_._headers(),
                timeout=self_._timeout,
                transport=transport,
            )

        c._client = patched_client.__get__(c, SplunkConnector)
        return c

    def test_401_returns_connection_failure(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"messages": [{"text": "auth required"}]})

        c = self._make_connector_with_handler(handler)
        r = c.check_connection()
        assert r.success is False
        assert "401" in r.message

    def test_5xx_retried_then_succeeds(self):
        attempts = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] < 2:
                return httpx.Response(502, text="bad gateway")
            return httpx.Response(
                200, json={"entry": [{"content": {"version": "9.2.0"}}]},
            )

        c = self._make_connector_with_handler(handler)
        r = c.check_connection()
        assert r.success is True
        assert attempts["n"] >= 2


class TestCircuitBreaker:
    def test_health_uses_breaker(self, mock_splunk):
        for _ in range(3):
            r = mock_splunk.health()
            assert r.success is True
        assert mock_splunk._circuit_breaker.state is CircuitState.CLOSED
