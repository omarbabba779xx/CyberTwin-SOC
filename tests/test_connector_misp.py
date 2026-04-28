"""MISP TI connector tests (mock_mode)."""
from __future__ import annotations

import pytest

from backend.connectors.base import ConnectorError
from backend.connectors.misp import MISPConnector


def test_describe_health_lookup():
    c = MISPConnector(url="http://misp.local", api_key="k", mock_mode=True)
    assert c.describe()["name"] == "misp"
    assert c.health().success is True
    r = c.lookup("1.2.3.4", indicator_type="ip-dst")
    assert r.success is True
    assert len(r.data["attributes"]) >= 1


def test_lookup_empty_raises():
    c = MISPConnector(mock_mode=True)
    with pytest.raises(ConnectorError, match="indicator is required"):
        c.lookup("  ")


def test_requires_credentials_live():
    c = MISPConnector(url="", api_key="", mock_mode=False)
    assert c.check_connection().success is False
