"""TheHive 5+ SOAR connector — production-grade implementation.

Wraps TheHive's REST API (v1) with:
- API-key authentication
- explicit timeout per call
- @with_retry exponential backoff on transient HTTP failures
- circuit breaker (inherited from BaseConnector)
- pagination cursor on list_cases
- structured error mapping (4xx → ConnectorError with body, 5xx → retried)
- mock_mode for offline integration tests / dev environments

Reference: https://docs.strangebee.com/thehive/api-docs/
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator, Optional

import httpx

from .base import ConnectorError, ConnectorResult, SOARConnector
from .registry import register
from .resilience import with_retry

logger = logging.getLogger("cybertwin.connectors.thehive")


_SEVERITY_MAP = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@register
class TheHiveConnector(SOARConnector):
    """TheHive v1 REST API client."""

    name = "thehive"

    def __init__(
        self,
        url: str = "",
        api_key: str = "",
        organisation: str = "",
        timeout: float = 10.0,
        verify_ssl: bool = True,
        mock_mode: bool = False,
        **extra: Any,
    ) -> None:
        super().__init__(
            url=url, api_key=api_key, organisation=organisation,
            timeout=timeout, verify_ssl=verify_ssl,
            mock_mode=mock_mode, **extra,
        )
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._organisation = organisation
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._mock_mode = mock_mode
        self._mock_state: list[dict[str, Any]] = []  # in-memory case store for tests

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if self._organisation:
            h["X-Organisation"] = self._organisation
        return h

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._url,
            headers=self._headers(),
            timeout=self._timeout,
            verify=self._verify_ssl,
        )

    @with_retry(
        max_retries=3, backoff_factor=0.5,
        retryable_exceptions=(
            httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError,
        ),
    )
    def _request(self, method: str, path: str, *,
                 json_body: Optional[dict] = None,
                 params: Optional[dict] = None) -> dict:
        """Execute *method* against *path* with structured error mapping.

        4xx responses raise ConnectorError immediately (not retried).
        5xx responses raise httpx.HTTPStatusError which @with_retry retries.
        """
        if self._mock_mode:
            return self._mock_handle(method, path, json_body or {}, params or {})

        with self._client() as client:
            try:
                resp = client.request(method, path, json=json_body, params=params)
            except httpx.HTTPError:
                raise

        if resp.status_code >= 500:
            # transient — let with_retry handle it
            resp.raise_for_status()

        if resp.status_code >= 400:
            # permanent — map the response body into a ConnectorError
            body: Any
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            raise ConnectorError(
                f"TheHive {method} {path} failed: {resp.status_code} {body}"
            )

        if not resp.content:
            return {}
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"TheHive returned invalid JSON: {exc}")

    # ------------------------------------------------------------------
    # In-memory mock for tests / offline dev
    # ------------------------------------------------------------------

    def _mock_handle(self, method: str, path: str, body: dict,
                     params: dict | None = None) -> dict:
        method = method.upper()
        params = params or {}
        if path == "/api/status":
            return {"versions": {"TheHive": "5.2.0-test"}}
        if path == "/api/v1/case" and method == "POST":
            case = {
                "_id": f"~mock-{len(self._mock_state) + 1}",
                "title": body.get("title", ""),
                "description": body.get("description", ""),
                "severity": body.get("severity", 2),
                "tags": list(body.get("tags", []) or []),
                "observables": [],
                "tasks": [],
            }
            self._mock_state.append(case)
            return case
        if path == "/api/v1/case" and method == "GET":
            rng = params.get("range", "")
            if rng and "-" in rng:
                start_s, end_s = rng.split("-", 1)
                try:
                    start = int(start_s)
                    end = int(end_s)
                except ValueError:
                    start, end = 0, len(self._mock_state)
                page = self._mock_state[start:end + 1]
                return {"data": list(page)}
            return {"data": list(self._mock_state)}
        if path.startswith("/api/v1/case/") and path.endswith("/observable") and method == "POST":
            cid = path.split("/")[4]
            case = next((c for c in self._mock_state if c["_id"] == cid), None)
            if not case:
                raise ConnectorError(f"mock: unknown case {cid}")
            obs = {"_id": f"~obs-{len(case['observables']) + 1}", **body}
            case["observables"].append(obs)
            return obs
        if path.startswith("/api/v1/case/") and path.endswith("/task") and method == "POST":
            cid = path.split("/")[4]
            case = next((c for c in self._mock_state if c["_id"] == cid), None)
            if not case:
                raise ConnectorError(f"mock: unknown case {cid}")
            task = {"_id": f"~task-{len(case['tasks']) + 1}", **body}
            case["tasks"].append(task)
            return task
        raise ConnectorError(f"mock: unsupported {method} {path}")

    # ------------------------------------------------------------------
    # SOARConnector interface
    # ------------------------------------------------------------------

    def check_connection(self) -> ConnectorResult:
        """GET /api/status — confirms reachability + auth."""
        if not self._url and not self._mock_mode:
            return ConnectorResult(success=False, message="TheHive URL not configured")
        if not self._api_key and not self._mock_mode:
            return ConnectorResult(success=False, message="TheHive API key not configured")
        try:
            data = self._request("GET", "/api/status")
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(
            success=True,
            message="TheHive reachable",
            data={"version": (data.get("versions") or {}).get("TheHive", "unknown")},
        )

    def create_case(
        self,
        *,
        title: str,
        description: str = "",
        severity: str = "medium",
        tags: Optional[list[str]] = None,
    ) -> ConnectorResult:
        if not title:
            raise ConnectorError("title is required")
        body = {
            "title": title,
            "description": description,
            "severity": _SEVERITY_MAP.get(severity.lower(), 2),
            "tags": list(tags or []),
        }
        try:
            case = self._request("POST", "/api/v1/case", json_body=body)
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(
            success=True, message="case created",
            data={"case_id": case.get("_id"), "title": case.get("title")},
        )

    def add_observable(self, case_id: str, *, data_type: str, data: str) -> ConnectorResult:
        if not case_id:
            raise ConnectorError("case_id is required")
        body = {"dataType": data_type, "data": data}
        try:
            obs = self._request(
                "POST", f"/api/v1/case/{case_id}/observable", json_body=body,
            )
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(success=True, message="observable added",
                               data={"observable_id": obs.get("_id")})

    def add_task(self, case_id: str, *, title: str, description: str = "") -> ConnectorResult:
        if not case_id:
            raise ConnectorError("case_id is required")
        body = {"title": title, "description": description}
        try:
            task = self._request(
                "POST", f"/api/v1/case/{case_id}/task", json_body=body,
            )
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(success=True, message="task added",
                               data={"task_id": task.get("_id")})

    # ------------------------------------------------------------------
    # Pagination over case listings
    # ------------------------------------------------------------------

    def list_cases(self, *, page_size: int = 50,
                   max_pages: int = 100) -> Iterator[dict[str, Any]]:
        """Yield cases page-by-page using TheHive's `range=` cursor."""
        for page in range(max_pages):
            start = page * page_size
            end = start + page_size - 1
            try:
                data = self._request(
                    "GET", "/api/v1/case",
                    params={"range": f"{start}-{end}"},
                )
            except ConnectorError as exc:
                logger.warning("list_cases stopped at page %d: %s", page, exc)
                return
            cases = data.get("data") if isinstance(data, dict) else data
            if not cases:
                return
            for case in cases:
                yield case
            if len(cases) < page_size:
                return
