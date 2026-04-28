"""Jira connector tests (mock_mode)."""
from __future__ import annotations

from backend.connectors.jira import JiraConnector


def test_describe_and_health():
    c = JiraConnector(
        url="https://test.atlassian.net",
        email="a@b.com",
        api_token="t",
        project_key="SOC",
        mock_mode=True,
    )
    assert c.describe()["name"] == "jira"
    assert c.health().success is True


def test_create_ticket_mock():
    c = JiraConnector(
        url="https://test.atlassian.net",
        email="a@b.com",
        api_token="t",
        mock_mode=True,
    )
    out = c.create_ticket(
        summary="Case handoff",
        description="SOC queue",
        priority="high",
        labels=["triage"],
    )
    assert out.success is True
    assert out.data.get("issue_key", "").startswith("SOC")


def test_requires_url_live():
    c = JiraConnector(url="", email="a", api_token="b", mock_mode=False)
    assert c.check_connection().success is False
