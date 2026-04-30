"""Affected assets, compliance impact, analyst confidence, and timestamp helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any


class ReportingMixin:
    """Builds the structured reporting sections + shared format helpers."""

    @staticmethod
    def _build_affected_assets(
        affected_hosts: list[str],
        alerts: list[dict],
        incidents: list[dict],
        timeline: list[dict],
    ) -> list[dict[str, Any]]:
        assets: list[dict[str, Any]] = []

        for host in affected_hosts:
            host_alerts = [a for a in alerts if a.get("affected_host") == host or a.get("src_host") == host]
            host_events = [t for t in timeline if t.get("is_malicious") and t.get("src_host") == host]
            host_tactics = list({a.get("tactic", "Unknown") for a in host_alerts if a.get("tactic")})

            related_incidents = [
                inc.get("incident_id", "")
                for inc in incidents
                if host in inc.get("affected_hosts", [])
            ]

            severities = [a.get("severity", "low") for a in host_alerts]
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_sev = max((sev_map.get(s, 1) for s in severities), default=1)
            host_risk = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(max_sev, "Low")

            assets.append({
                "hostname": host,
                "risk_level": host_risk,
                "alert_count": len(host_alerts),
                "malicious_event_count": len(host_events),
                "tactics_observed": host_tactics,
                "related_incidents": related_incidents,
                "assessment": (
                    f"Host {host} was involved in {len(host_events)} malicious event(s) "
                    f"and triggered {len(host_alerts)} alert(s). "
                    f"Observed tactics: {', '.join(host_tactics) if host_tactics else 'none identified'}. "
                    f"Risk level: {host_risk}."
                ),
            })

        return assets

    @staticmethod
    def _build_compliance_impact(
        scenario_type: str,
        severity: str,
        scores: dict,
        affected_hosts: list[str],
        affected_users: list[str],
        iocs: dict[str, list[str]],
    ) -> dict[str, Any]:
        overall = scores.get("overall_score", 0)
        compromised = iocs.get("compromised_accounts", [])

        gdpr: dict[str, Any] = {
            "relevant": len(affected_users) > 0 or len(compromised) > 0,
            "findings": [],
        }
        if gdpr["relevant"]:
            gdpr["findings"].append(
                f"Potential personal data exposure involving {len(affected_users)} user account(s). "
                f"Under GDPR Article 33, the supervisory authority must be notified within 72 hours "
                f"if personal data breach is confirmed."
            )
            if scenario_type == "exfiltration":
                gdpr["findings"].append(
                    "Data exfiltration was observed, which may constitute a reportable breach "
                    "under GDPR Article 34 if natural persons' data was affected."
                )

        iso27001: dict[str, Any] = {
            "relevant": True,
            "findings": [],
        }
        if overall < 60:
            iso27001["findings"].append(
                f"Overall score ({overall}/100) falls below acceptable thresholds for "
                f"ISO 27001 Annex A controls A.12.4 (Logging and Monitoring) and "
                f"A.16.1 (Information Security Incident Management). Non-conformity "
                f"should be documented and addressed in the corrective action process."
            )
        iso27001["findings"].append(
            "Review applicability of controls A.12.6 (Technical Vulnerability Management) "
            "and A.13.1 (Network Security Management) based on attack vectors observed."
        )

        nist: dict[str, Any] = {
            "relevant": True,
            "findings": [],
        }
        det_score = scores.get("detection_score", 0)
        if det_score < 50:
            nist["findings"].append(
                f"NIST CSF Detect function scored {det_score}%, indicating gaps in "
                f"DE.CM (Security Continuous Monitoring) and DE.DP (Detection Processes). "
                f"Recommend alignment with NIST SP 800-53 SI-4 (Information System Monitoring)."
            )
        nist["findings"].append(
            "Evaluate alignment with NIST CSF categories: ID.RA (Risk Assessment), "
            "PR.DS (Data Security), DE.AE (Anomalies and Events), and RS.RP (Response Planning)."
        )

        return {
            "gdpr": gdpr,
            "iso_27001": iso27001,
            "nist_csf": nist,
            "summary": (
                f"This incident has potential implications under GDPR "
                f"({'applicable' if gdpr['relevant'] else 'not directly applicable'}), "
                f"ISO 27001 (review recommended), and NIST CSF (alignment assessment needed). "
                f"Legal and compliance teams should be engaged to determine formal notification "
                f"and remediation obligations."
            ),
        }

    @staticmethod
    def _build_confidence(
        scores: dict,
        alerts: list[dict],
        incidents: list[dict],
        logs_stats: dict,
        timeline: list[dict],
    ) -> dict[str, Any]:
        factors: list[str] = []
        confidence = 70  # base confidence

        total_logs = logs_stats.get("total_logs", 0)
        if total_logs > 500:
            confidence += 10
            factors.append(f"High data volume ({total_logs} log events) provides strong statistical basis.")
        elif total_logs > 100:
            confidence += 5
            factors.append(f"Moderate data volume ({total_logs} log events) provides adequate basis.")
        else:
            confidence -= 10
            factors.append(f"Low data volume ({total_logs} log events) may limit analysis accuracy.")

        if len(incidents) > 0:
            confidence += 5
            factors.append(
                f"{len(incidents)} correlated incident(s) confirm multi-stage attack pattern."
            )
        else:
            confidence -= 5
            factors.append("No correlated incidents reduces confidence in attack chain reconstruction.")

        det = scores.get("detection_score", 0)
        if det >= 70:
            confidence += 5
            factors.append(f"High detection rate ({det}%) supports comprehensive analysis.")
        elif det < 30:
            confidence -= 10
            factors.append(
                f"Low detection rate ({det}%) means large portions of the attack were "
                f"unobserved, reducing analytical certainty."
            )

        vis = scores.get("visibility_score", 0)
        if vis >= 70:
            confidence += 5
            factors.append(f"Good log source visibility ({vis}%) across the environment.")
        elif vis < 40:
            confidence -= 10
            factors.append(f"Limited visibility ({vis}%) creates blind spots in the analysis.")

        confidence = max(10, min(95, confidence))

        if confidence >= 80:
            level = "High"
        elif confidence >= 55:
            level = "Medium"
        else:
            level = "Low"

        return {
            "score": confidence,
            "level": level,
            "reasoning": " ".join(factors),
        }

    @staticmethod
    def _format_ts(ts: str) -> str:
        if not ts or ts == "N/A":
            return "N/A"
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(ts, fmt)
                return dt.strftime("%Y-%m-%d at %H:%M:%S UTC")
            except (ValueError, TypeError):
                continue
        return ts
