"""Microsoft Sentinel / Azure Log Analytics connector (SIEM).

Uses the ``/v1/workspaces/{id}/query`` REST surface (Kusto over HTTP).

Reference: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview
"""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from .base import ConnectorError, ConnectorResult, SIEMConnector
from .registry import register
from .resilience import with_retry


@register
class SentinelConnector(SIEMConnector):
    """Azure Log Analytics REST client (Sentinel-backed workspace)."""

    name = "sentinel"

    def __init__(
        self,
        workspace_id: str = "",
        token: str = "",
        tenant_id: str = "",
        timeout: float = 30.0,
        verify_ssl: bool = True,
        mock_mode: bool = False,
        **extra: Any,
    ) -> None:
        super().__init__(
            workspace_id=workspace_id,
            token=token,
            tenant_id=tenant_id,
            timeout=timeout,
            verify_ssl=verify_ssl,
            mock_mode=mock_mode,
            **extra,
        )
        self._workspace_id = workspace_id.strip()
        self._token = token
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._mock_mode = mock_mode
        self._base = "https://api.loganalytics.io"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._base,
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
    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict] = None,
    ) -> dict:
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
            raise ConnectorError(
                f"Sentinel {method} {path} failed: {resp.status_code} {body}"
            )
        if not resp.content:
            return {}
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"Sentinel invalid JSON: {exc}")

    def _mock_handle(self, method: str, path: str, body: dict) -> dict:
        m = method.upper()
        if m == "POST" and path.endswith("/query"):
            return {
                "tables": [{
                    "name": "PrimaryResult",
                    "rows": [["mock-row-1"], ["mock-row-2"]],
                    "columns": [{"name": "RawMessage", "type": "string"}],
                }],
            }
        raise ConnectorError(f"sentinel mock: unsupported {m} {path}")

    def check_connection(self) -> ConnectorResult:
        if not self._workspace_id and not self._mock_mode:
            return ConnectorResult(success=False, message="workspace_id not configured")
        if not self._token and not self._mock_mode:
            return ConnectorResult(success=False, message="token not configured")
        wid = self._workspace_id or "00000000-0000-0000-0000-000000000001"
        path = f"/v1/workspaces/{wid}/query"
        try:
            data = self._request(
                "POST",
                path,
                json_body={"query": "Heartbeat | take 1"},
            )
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(
            success=True,
            message="Sentinel / Log Analytics reachable",
            data={"sample": data},
        )

    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        if not query:
            raise ConnectorError("query is required")
        wid = self._workspace_id or "00000000-0000-0000-0000-000000000001"
        path = f"/v1/workspaces/{wid}/query"
        try:
            data = self._request("POST", path, json_body={"query": query[:8000]})
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        rows: list[Any] = []
        for table in data.get("tables") or []:
            for row in table.get("rows") or []:
                rows.append(row)
                if len(rows) >= limit:
                    break
            if len(rows) >= limit:
                break
        return ConnectorResult(
            success=True,
            message="query complete",
            data={"results": rows[:limit], "count": len(rows[:limit])},
        )

    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        """Native Sentinel incident creation uses Graph / ARM; keep explicit opt-in."""
        if self._mock_mode:
            return ConnectorResult(
                success=True,
                message="alert recorded (mock)",
                data={"incident_id": "mock-sentinel-incident", "alert": alert},
            )
        return ConnectorResult(
            success=False,
            message="push_alert needs Microsoft Graph Security incidents API",
            data={"hint": "use alert rules or automation playbooks in production"},
        )
