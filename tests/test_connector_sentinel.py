"""Sentinel / Log Analytics connector tests (mock_mode)."""
from __future__ import annotations

import pytest

from backend.connectors.base import ConnectorError
from backend.connectors.sentinel import SentinelConnector


@pytest.fixture
def mock_sentinel():
    return SentinelConnector(
        workspace_id="00000000-0000-0000-0000-000000000001",
        token="mock-token",
        mock_mode=True,
    )


def test_describe_lists_keys(mock_sentinel):
    d = mock_sentinel.describe()
    assert d["name"] == "sentinel"
    assert d["kind"] == "siem"


def test_health_succeeds(mock_sentinel):
    r = mock_sentinel.health()
    assert r.success is True


def test_check_connection(mock_sentinel):
    r = mock_sentinel.check_connection()
    assert r.success is True
    assert "sample" in r.data


def test_search_requires_query(mock_sentinel):
    with pytest.raises(ConnectorError, match="query is required"):
        mock_sentinel.search("")


def test_search_returns_rows(mock_sentinel):
    r = mock_sentinel.search("Heartbeat | take 5", limit=2)
    assert r.success is True
    assert len(r.data["results"]) <= 2


def test_push_alert_mock(mock_sentinel):
    r = mock_sentinel.push_alert({"title": "x"})
    assert r.success is True


def test_requires_workspace_when_not_mock():
    c = SentinelConnector(workspace_id="", token="")
    r = c.check_connection()
    assert r.success is False
