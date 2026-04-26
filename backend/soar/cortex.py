"""
CyberTwin SOC — Cortex v3 API Client
======================================
Submits IOCs/observables from simulation results to Cortex analyzers
for automated enrichment (VirusTotal, AbuseIPDB, Shodan, etc.).

Environment variables:
    CORTEX_URL      — Cortex base URL (e.g. http://cortex:9001)
    CORTEX_API_KEY  — Cortex API key
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

import httpx

logger = logging.getLogger("cybertwin.soar.cortex")


class CortexClient:
    """HTTP client for Cortex 3.x REST API."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.url = (url or os.getenv("CORTEX_URL", "http://cortex:9001")).rstrip("/")
        self.api_key = api_key or os.getenv("CORTEX_API_KEY", "")
        self._timeout = timeout
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def check_connection(self) -> dict[str, Any]:
        """Return Cortex status or error dict."""
        try:
            resp = httpx.get(
                f"{self.url}/api/status",
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return {"connected": True, "version": data.get("version", "?"), "url": self.url}
        except Exception as exc:
            logger.warning("Cortex connection check failed: %s", exc)
            return {"connected": False, "error": str(exc), "url": self.url}

    # ------------------------------------------------------------------
    # Analyzers
    # ------------------------------------------------------------------

    def list_analyzers(self, data_type: Optional[str] = None) -> list[dict[str, Any]]:
        """Return available analyzers, optionally filtered by data type."""
        path = f"/api/analyzer/type/{data_type}" if data_type else "/api/analyzer"
        try:
            resp = httpx.get(f"{self.url}{path}", headers=self._headers, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("Cortex list_analyzers failed: %s", exc)
            return []

    def run_analyzer(
        self,
        analyzer_id: str,
        data_type: str,
        data: str,
        tlp: int = 2,
    ) -> dict[str, Any]:
        """Submit an observable to a Cortex analyzer and return the job."""
        payload = {
            "dataType": data_type,
            "data": data,
            "tlp": tlp,
        }
        try:
            resp = httpx.post(
                f"{self.url}/api/analyzer/{analyzer_id}/run",
                headers=self._headers,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            job = resp.json()
            logger.info("Cortex job submitted: %s for %s/%s", job.get("id"), analyzer_id, data)
            return {"success": True, "job_id": job.get("id"), "status": job.get("status"), "job": job}
        except httpx.HTTPStatusError as exc:
            logger.error("Cortex run_analyzer HTTP %s: %s", exc.response.status_code, exc.response.text)
            return {"success": False, "error": f"HTTP {exc.response.status_code}: {exc.response.text}"}
        except Exception as exc:
            logger.error("Cortex run_analyzer failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def get_job_report(self, job_id: str, wait: bool = False, max_wait: int = 60) -> dict[str, Any]:
        """Get the report for a completed Cortex job.

        Args:
            job_id:   The Cortex job ID.
            wait:     If True, poll until the job is complete (up to max_wait seconds).
            max_wait: Maximum number of seconds to wait when wait=True.
        """
        deadline = time.time() + max_wait
        while True:
            try:
                resp = httpx.get(
                    f"{self.url}/api/job/{job_id}/report",
                    headers=self._headers,
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                status = data.get("status", "")
                if not wait or status in ("Success", "Failure") or time.time() > deadline:
                    return {"success": True, "status": status, "report": data}
                time.sleep(3)
            except Exception as exc:
                logger.error("Cortex get_job_report failed: %s", exc)
                return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def analyze_iocs(
        self,
        iocs: list[str],
        preferred_analyzers: Optional[list[str]] = None,
        tlp: int = 2,
    ) -> list[dict[str, Any]]:
        """
        Submit a list of IOCs to the first compatible Cortex analyzer.
        Returns a list of submitted job results.
        """
        preferred_analyzers = preferred_analyzers or [
            "VirusTotal_GetReport_3_1",
            "AbuseIPDB_1_0",
            "Shodan_DNSResolve_1_0",
            "URLhaus_2_0",
        ]

        results = []
        for ioc in iocs[:10]:
            ioc_str = str(ioc)
            data_type = _infer_data_type(ioc_str)
            submitted = False
            for analyzer_id in preferred_analyzers:
                job = self.run_analyzer(analyzer_id, data_type, ioc_str, tlp=tlp)
                if job["success"]:
                    results.append({"ioc": ioc_str, "analyzer": analyzer_id, "job_id": job["job_id"]})
                    submitted = True
                    break
            if not submitted:
                results.append({"ioc": ioc_str, "analyzer": None, "error": "No compatible analyzer found"})
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_data_type(value: str) -> str:
    """Best-effort data type inference for a raw IOC string."""
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", value) or re.match(r"^[a-fA-F0-9]{64}$", value):
        return "hash"
    if re.match(r"^https?://", value):
        return "url"
    if re.match(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$", value):
        return "domain"
    return "other"
