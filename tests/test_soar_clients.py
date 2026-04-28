"""Smoke tests for `backend/soar/` HTTP clients."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_cortex_check_connection(monkeypatch):
    from backend.soar import cortex as cx

    def fake_get(url, **kwargs):  # noqa: ARG001
        assert "/api/status" in url
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "3.2"}
        resp.raise_for_status.return_value = None
        return resp

    monkeypatch.setattr(cx.httpx, "get", fake_get)
    c = cx.CortexClient(url="http://cortex:9001", api_key="k")
    out = c.check_connection()
    assert out["connected"] is True
    assert out["version"] == "3.2"


def test_thehive_check_connection(monkeypatch):
    from backend.soar import thehive as th

    def fake_get(url, **kwargs):  # noqa: ARG001
        assert "/api/v1/status" in url
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"versions": {"TheHive": "5.3"}}
        resp.raise_for_status.return_value = None
        return resp

    monkeypatch.setattr(th.httpx, "get", fake_get)
    c = th.TheHiveClient(url="http://thehive:9000", api_key="k")
    out = c.check_connection()
    assert out["connected"] is True
    assert "5.3" in str(out.get("version", ""))


@pytest.mark.parametrize(
    "ioc,expected",
    [
        ("8.8.8.8", "ip"),
        ("deadbeef" * 4, "hash"),
        ("https://evil.test/x", "url"),
        ("foo.bar", "domain"),
    ],
)
def test_cortex_infer_data_type(ioc, expected):
    from backend.soar.cortex import _infer_data_type

    assert _infer_data_type(ioc) == expected
