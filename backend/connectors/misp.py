"""MISP (Malware Information Sharing Platform) TI connector.

REST search via ``POST /attributes/restSearch``.
"""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from .base import ConnectorError, ConnectorResult, TIConnector
from .registry import register
from .resilience import with_retry


@register
class MISPConnector(TIConnector):
    name = "misp"

    def __init__(
        self,
        url: str = "",
        api_key: str = "",
        timeout: float = 30.0,
        verify_ssl: bool = True,
        mock_mode: bool = False,
        **extra: Any,
    ) -> None:
        super().__init__(
            url=url,
            api_key=api_key,
            timeout=timeout,
            verify_ssl=verify_ssl,
            mock_mode=mock_mode,
            **extra,
        )
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._mock_mode = mock_mode

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
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
    def _request(self, method: str, path: str,
                 *, json_body: Optional[dict] = None) -> dict:
        if self._mock_mode:
            return self._mock_handle(method, path, json_body or {})
        with self._client() as client:
            if method.upper() == "GET":
                resp = client.get(path)
            else:
                resp = client.request(method, path, json=json_body)
        if resp.status_code >= 500:
            resp.raise_for_status()
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            raise ConnectorError(f"MISP {method} {path}: {resp.status_code} {body}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"MISP invalid JSON: {exc}")

    def _mock_handle(self, method: str, path: str, body: dict) -> dict:
        m = method.upper()
        if "users/view/me" in path and m == "POST":
            return {"User": {"email": "soc@mock.local", "role_id": "1"}}
        if "getVersion" in path and m == "GET":
            return {"version": "2.5.999-mock"}
        if "restsearch" in path.lower() and m == "POST":
            value = ""
            ps = body.get("value") if isinstance(body.get("value"), list) else [body.get("value", "")]
            value = str(ps[0] if ps else "x")
            return {
                "response": {"Attribute": [
                    {"id": "1", "type": "ip-dst", "value": value, "timestamp": "0"},
                ]},
            }
        raise ConnectorError(f"misp mock: unsupported {m} {path}")

    def check_connection(self) -> ConnectorResult:
        if not self._url and not self._mock_mode:
            return ConnectorResult(success=False, message="MISP URL not configured")
        if not self._api_key and not self._mock_mode:
            return ConnectorResult(success=False, message="MISP API key not configured")
        try:
            data = self._request("POST", "/users/view/me.json", json_body={})
        except ConnectorError:
            try:
                data = self._request(
                    "GET",
                    "/servers/getVersion.json",
                )
            except ConnectorError as exc:
                return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(success=True, message="MISP reachable", data={"me": data})

    def lookup(
        self,
        indicator: str,
        *,
        indicator_type: Optional[str] = None,
    ) -> ConnectorResult:
        if not indicator.strip():
            raise ConnectorError("indicator is required")
        body: dict[str, Any] = {"returnFormat": "json", "limit": 50}
        if indicator_type:
            body["type"] = indicator_type
        body["value"] = [indicator.strip()]
        path = "/attributes/restSearch"
        try:
            data = self._request("POST", path, json_body=body)
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        attrs = data.get("response", {}).get("Attribute", [])
        if isinstance(attrs, dict):
            attrs = [attrs]
        return ConnectorResult(
            success=True,
            message=f"{len(attrs)} attribute(s)",
            data={"indicator": indicator, "attributes": attrs},
        )
