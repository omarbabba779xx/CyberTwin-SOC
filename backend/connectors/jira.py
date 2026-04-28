"""Atlassian Jira Cloud connector (ITSM).

REST API v3: https://developer.atlassian.com/cloud/jira/platform/rest/v3/
"""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from .base import ConnectorError, ConnectorResult, ITSMConnector
from .registry import register
from .resilience import with_retry


@register
class JiraConnector(ITSMConnector):
    name = "jira"

    def __init__(
        self,
        url: str = "",
        email: str = "",
        api_token: str = "",
        project_key: str = "SOC",
        timeout: float = 30.0,
        verify_ssl: bool = True,
        mock_mode: bool = False,
        **extra: Any,
    ) -> None:
        super().__init__(
            url=url,
            email=email,
            api_token=api_token,
            project_key=project_key,
            timeout=timeout,
            verify_ssl=verify_ssl,
            mock_mode=mock_mode,
            **extra,
        )
        self._url = url.rstrip("/")
        self._email = email
        self._token = api_token
        self._project = project_key
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._mock_mode = mock_mode
        self._mock_issues: list[dict[str, Any]] = []

    def _headers(self) -> dict[str, str]:
        import base64

        pair = f"{self._email}:{self._token}".encode()
        b64 = base64.b64encode(pair).decode("ascii")
        return {
            "Authorization": f"Basic {b64}",
            "Content-Type": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._url,
            headers=self._headers(),
            timeout=self._timeout,
            verify=self._verify_ssl,
        )

    @with_retry(
        max_retries=3,
        backoff_factor=0.5,
        retryable_exceptions=(
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.HTTPStatusError,
        ),
    )
    def _request(self, method: str, path: str, *,
                 json_body: Optional[dict] = None) -> dict:
        if self._mock_mode:
            return self._mock_handle(method, path, json_body or {})
        with self._client() as client:
            resp = client.request(method, path, json=json_body)
        if resp.status_code >= 500:
            resp.raise_for_status()
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            raise ConnectorError(f"Jira {method} {path}: {resp.status_code} {body}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"Jira invalid JSON: {exc}")

    def _mock_handle(self, method: str, path: str, body: dict) -> dict:
        m = method.upper()
        if "/myself" in path and m == "GET":
            return {"displayName": "SOC Bot", "emailAddress": self._email}
        if "/issue" in path and m == "POST":
            key = f"{self._project}-{len(self._mock_issues) + 1}"
            issue = {"id": key, "key": key, "self": f"{self._url}/rest/api/3/issue/{key}"}
            self._mock_issues.append({"fields": body.get("fields", {})})
            return issue
        raise ConnectorError(f"jira mock: unsupported {m} {path}")

    def check_connection(self) -> ConnectorResult:
        if not self._url and not self._mock_mode:
            return ConnectorResult(success=False, message="Jira URL not configured")
        if (not self._email or not self._token) and not self._mock_mode:
            return ConnectorResult(success=False, message="Jira credentials not configured")
        try:
            data = self._request("GET", "/rest/api/3/myself")
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        name = data.get("displayName", "?")
        return ConnectorResult(success=True, message=f"connected as {name}")

    def create_ticket(
        self,
        *,
        summary: str,
        description: str = "",
        priority: str = "medium",
        labels: Optional[list[str]] = None,
    ) -> ConnectorResult:
        prio_map = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Highest"}
        payload = {
            "fields": {
                "project": {"key": self._project},
                "summary": summary[:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description[:32000]}],
                        },
                    ],
                },
                "issuetype": {"name": "Task"},
                "priority": {"name": prio_map.get(priority.lower(), "Medium")},
                "labels": labels or ["cybertwin-soc"],
            },
        }
        try:
            data = self._request("POST", "/rest/api/3/issue", json_body=payload)
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(
            success=True,
            message="ticket created",
            data={"issue_key": data.get("key"), "id": data.get("id")},
        )
