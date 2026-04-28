"""Splunk SIEM connector — production-grade implementation.

Wraps the Splunk REST API (`/services/`) with:
- token-based authentication
- explicit timeout per call
- @with_retry exponential backoff on transient HTTP failures
- circuit breaker (inherited from BaseConnector)
- search-job lifecycle (POST /search/jobs → poll status → GET results)
- pagination via offset/count
- structured error mapping (4xx → ConnectorError, 5xx → retried)
- mock_mode for integration tests

Reference: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

import httpx

from .base import ConnectorError, ConnectorResult, SIEMConnector
from .registry import register
from .resilience import with_retry

logger = logging.getLogger("cybertwin.connectors.splunk")


@register
class SplunkConnector(SIEMConnector):
    """Splunk Enterprise / Cloud REST client."""

    name = "splunk"

    def __init__(
        self,
        url: str = "",
        token: str = "",
        timeout: float = 30.0,
        verify_ssl: bool = True,
        index_default: str = "main",
        mock_mode: bool = False,
        **extra: Any,
    ) -> None:
        super().__init__(
            url=url, token=token, timeout=timeout,
            verify_ssl=verify_ssl, index_default=index_default,
            mock_mode=mock_mode, **extra,
        )
        self._url = url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._index = index_default
        self._mock_mode = mock_mode
        self._mock_jobs: dict[str, dict[str, Any]] = {}
        self._mock_alerts: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

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
                 data: Optional[dict] = None,
                 params: Optional[dict] = None) -> dict:
        """Execute *method* against Splunk *path* with error mapping."""
        if self._mock_mode:
            return self._mock_handle(method, path, data or {}, params or {})

        with self._client() as client:
            resp = client.request(method, path, data=data, params=params)

        if resp.status_code >= 500:
            resp.raise_for_status()

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            raise ConnectorError(
                f"Splunk {method} {path} failed: {resp.status_code} {body}"
            )

        if not resp.content:
            return {}
        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"Splunk returned invalid JSON: {exc}")

    # ------------------------------------------------------------------
    # In-memory mock for tests
    # ------------------------------------------------------------------

    def _mock_handle(self, method: str, path: str,
                     data: dict, params: dict) -> dict:
        method = method.upper()
        if path == "/services/server/info" and method == "GET":
            return {"entry": [{"content": {"version": "9.2.0-mock"}}]}
        if path == "/services/search/jobs" and method == "POST":
            sid = f"mock-job-{len(self._mock_jobs) + 1}"
            self._mock_jobs[sid] = {
                "search": data.get("search", ""),
                "status": "DONE",
                "results": [
                    {"_raw": "mock event 1", "host": "WS01", "user": "alice"},
                    {"_raw": "mock event 2", "host": "WS01", "user": "bob"},
                ],
            }
            return {"sid": sid}
        if path.startswith("/services/search/jobs/") and path.endswith("/results"):
            sid = path.split("/")[4]
            job = self._mock_jobs.get(sid)
            if not job:
                raise ConnectorError(f"mock: unknown job {sid}")
            offset = int(params.get("offset", 0))
            count = int(params.get("count", 100))
            page = job["results"][offset:offset + count]
            return {"results": page, "offset": offset, "count": len(page)}
        if path.startswith("/services/search/jobs/"):
            sid = path.split("/")[4]
            job = self._mock_jobs.get(sid)
            if not job:
                raise ConnectorError(f"mock: unknown job {sid}")
            return {"entry": [{"content": {"dispatchState": job["status"]}}]}
        if path.startswith("/services/receivers/simple") and method == "POST":
            self._mock_alerts.append({
                "index": params.get("index", self._index),
                "source": params.get("source", "cybertwin-soc"),
                "raw": data.get("raw", "") if isinstance(data, dict) else str(data),
            })
            return {"ok": True}
        raise ConnectorError(f"mock: unsupported {method} {path}")

    # ------------------------------------------------------------------
    # SIEMConnector interface
    # ------------------------------------------------------------------

    def check_connection(self) -> ConnectorResult:
        if not self._url and not self._mock_mode:
            return ConnectorResult(success=False, message="Splunk URL not configured")
        if not self._token and not self._mock_mode:
            return ConnectorResult(success=False, message="Splunk token not configured")
        try:
            data = self._request("GET", "/services/server/info")
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        version = "unknown"
        try:
            version = data["entry"][0]["content"]["version"]
        except (KeyError, IndexError, TypeError):
            pass
        return ConnectorResult(success=True, message="Splunk reachable",
                               data={"version": version})

    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        """Submit a search job, wait for completion, and return paginated results."""
        if not query:
            raise ConnectorError("query is required")

        try:
            job = self._request(
                "POST", "/services/search/jobs",
                data={"search": query, "output_mode": "json"},
            )
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))

        sid = job.get("sid")
        if not sid:
            return ConnectorResult(success=False,
                                   message="Splunk did not return a job sid")

        # Poll until job is DONE (or fail after a deadline)
        deadline = time.monotonic() + min(self._timeout, 60)
        while time.monotonic() < deadline:
            try:
                status = self._request(
                    "GET", f"/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                )
            except ConnectorError as exc:
                return ConnectorResult(success=False, message=str(exc))
            state = "UNKNOWN"
            try:
                state = status["entry"][0]["content"]["dispatchState"]
            except (KeyError, IndexError, TypeError):
                pass
            if state == "DONE":
                break
            if state == "FAILED":
                return ConnectorResult(success=False, message="search job failed",
                                       data={"sid": sid})
            time.sleep(0.5)
        else:
            return ConnectorResult(success=False, message="search job timed out",
                                   data={"sid": sid})

        # Page through results
        results: list[dict] = []
        offset = 0
        page_size = min(limit, 1000)
        while len(results) < limit:
            try:
                page = self._request(
                    "GET", f"/services/search/jobs/{sid}/results",
                    params={"offset": offset, "count": page_size, "output_mode": "json"},
                )
            except ConnectorError as exc:
                return ConnectorResult(success=False, message=str(exc),
                                       data={"sid": sid, "partial": results})
            chunk = page.get("results", []) if isinstance(page, dict) else []
            results.extend(chunk)
            if len(chunk) < page_size:
                break
            offset += page_size

        return ConnectorResult(
            success=True, message="search complete",
            data={"sid": sid, "results": results[:limit], "count": len(results[:limit])},
        )

    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        """POST a CyberTwin alert to a Splunk HEC-style /receivers/simple endpoint."""
        params = {
            "index": alert.get("index", self._index),
            "source": "cybertwin-soc",
            "sourcetype": "_json",
        }
        try:
            self._request(
                "POST", "/services/receivers/simple",
                data={"raw": json.dumps(alert, default=str)},
                params=params,
            )
        except ConnectorError as exc:
            return ConnectorResult(success=False, message=str(exc))
        return ConnectorResult(success=True, message="alert pushed",
                               data={"index": params["index"]})
