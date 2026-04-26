"""
CyberTwin SOC — TheHive v5 API Client
========================================
Pushes simulation incidents and alerts to a TheHive instance.
Supports TheHive 5.x REST API (Bearer token auth).

Environment variables:
    THEHIVE_URL      — TheHive base URL (e.g. http://thehive:9000)
    THEHIVE_API_KEY  — TheHive API key
    THEHIVE_ORG      — Organisation name (default: "cybertwin")
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger("cybertwin.soar.thehive")

_SEVERITY = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TLP = {"white": 0, "green": 1, "amber": 2, "red": 3}


class TheHiveClient:
    """HTTP client for TheHive 5.x REST API."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        org: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.url = (url or os.getenv("THEHIVE_URL", "http://thehive:9000")).rstrip("/")
        self.api_key = api_key or os.getenv("THEHIVE_API_KEY", "")
        self.org = org or os.getenv("THEHIVE_ORG", "cybertwin")
        self._timeout = timeout
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Organisation": self.org,
        }

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def check_connection(self) -> dict[str, Any]:
        """Return TheHive status or error dict."""
        try:
            resp = httpx.get(
                f"{self.url}/api/v1/status",
                headers=self._headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return {"connected": True, "version": data.get("versions", {}).get("TheHive", "?"),
                    "url": self.url}
        except Exception as exc:
            logger.warning("TheHive connection check failed: %s", exc)
            return {"connected": False, "error": str(exc), "url": self.url}

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        tags: Optional[list[str]] = None,
        tlp: str = "amber",
        pap: int = 2,
    ) -> dict[str, Any]:
        """Create a new case in TheHive and return the created case dict."""
        payload = {
            "title": title,
            "description": description,
            "severity": _SEVERITY.get(severity.lower(), 2),
            "startDate": int(datetime.now(timezone.utc).timestamp() * 1000),
            "tags": tags or ["cybertwin", "simulation"],
            "tlp": _TLP.get(tlp.lower(), 2),
            "pap": pap,
            "flag": False,
        }
        try:
            resp = httpx.post(
                f"{self.url}/api/v1/case",
                headers=self._headers,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            case = resp.json()
            logger.info("TheHive case created: #%s — %s", case.get("number"), title)
            return {"success": True, "case_id": case.get("_id"), "case_number": case.get("number"),
                    "case": case}
        except httpx.HTTPStatusError as exc:
            logger.error("TheHive create_case HTTP error %s: %s", exc.response.status_code, exc.response.text)
            return {"success": False, "error": f"HTTP {exc.response.status_code}: {exc.response.text}"}
        except Exception as exc:
            logger.error("TheHive create_case failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def add_observable(
        self,
        case_id: str,
        data_type: str,
        data: str,
        message: str = "",
        tlp: str = "amber",
    ) -> dict[str, Any]:
        """Add an observable (IOC) to an existing case."""
        payload = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tlp": _TLP.get(tlp.lower(), 2),
            "ioc": True,
        }
        try:
            resp = httpx.post(
                f"{self.url}/api/v1/case/{case_id}/observable",
                headers=self._headers,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return {"success": True, "observable": resp.json()}
        except Exception as exc:
            logger.error("TheHive add_observable failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def add_task(
        self,
        case_id: str,
        title: str,
        description: str = "",
        assignee: Optional[str] = None,
    ) -> dict[str, Any]:
        """Add a response task to a case."""
        payload = {"title": title, "description": description, "status": "Waiting"}
        if assignee:
            payload["assignee"] = assignee
        try:
            resp = httpx.post(
                f"{self.url}/api/v1/case/{case_id}/task",
                headers=self._headers,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return {"success": True, "task": resp.json()}
        except Exception as exc:
            logger.error("TheHive add_task failed: %s", exc)
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # High-level helpers
    # ------------------------------------------------------------------

    def push_simulation_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a CyberTwin simulation result into a TheHive case with
        observables (IOCs) and response tasks (recommendations).
        """
        scenario = result.get("scenario", {})
        score = result.get("overall_score", 0)
        risk = result.get("risk_level", "Unknown")
        alerts_count = result.get("total_alerts", 0)
        anomalies_count = result.get("total_anomalies", 0)

        severity = "high" if score < 50 else ("medium" if score < 75 else "low")

        title = f"[CyberTwin] {scenario.get('name', 'Simulation')} — Score {score:.1f}/100 ({risk})"

        description = (
            f"## CyberTwin SOC Simulation Report\n\n"
            f"**Scenario**: {scenario.get('name', 'N/A')}\n"
            f"**Category**: {scenario.get('category', 'N/A')}\n"
            f"**Overall Score**: {score:.1f} / 100\n"
            f"**Risk Level**: {risk}\n"
            f"**Maturity Level**: {result.get('maturity_level', 'N/A')}\n\n"
            f"### Detection Summary\n"
            f"- Alerts triggered: **{alerts_count}**\n"
            f"- ML Anomalies detected: **{anomalies_count}**\n"
            f"- Total events generated: **{result.get('total_events', 0)}**\n\n"
            f"### Scores\n"
            f"| Dimension | Score |\n|---|---|\n"
            f"| Detection | {result.get('scores', {}).get('detection', 0):.1f} |\n"
            f"| Coverage  | {result.get('scores', {}).get('coverage', 0):.1f} |\n"
            f"| Response  | {result.get('scores', {}).get('response', 0):.1f} |\n"
            f"| Visibility| {result.get('scores', {}).get('visibility', 0):.1f} |\n\n"
            f"### AI Analysis\n"
            f"{result.get('ai_analysis', {}).get('summary', '_No AI analysis available._')}\n"
        )

        tags = [
            "cybertwin", "simulation",
            scenario.get("category", "unknown"),
            f"risk:{risk.lower()}",
            f"score:{int(score)}",
        ]

        case_result = self.create_case(title, description, severity=severity, tags=tags)
        if not case_result["success"]:
            return case_result

        case_id = case_result["case_id"]
        observables_added = []
        tasks_added = []

        ai = result.get("ai_analysis", {})
        for ioc in ai.get("iocs", [])[:20]:
            ioc_str = str(ioc)
            data_type = "filename" if "\\" in ioc_str or "/" in ioc_str else "other"
            obs = self.add_observable(case_id, data_type, ioc_str, "IOC from CyberTwin simulation")
            if obs["success"]:
                observables_added.append(ioc_str)

        for rec in ai.get("recommendations", [])[:10]:
            task = self.add_task(case_id, rec[:64], description=str(rec))
            if task["success"]:
                tasks_added.append(rec)

        return {
            "success": True,
            "case_id": case_id,
            "case_number": case_result.get("case_number"),
            "thehive_url": f"{self.url}/cases/{case_id}",
            "observables_added": len(observables_added),
            "tasks_added": len(tasks_added),
        }
