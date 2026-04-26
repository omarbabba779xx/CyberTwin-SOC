"""
CyberTwin SOC - Report Generator
Produces comprehensive incident reports with scoring, MITRE mapping, and recommendations.
"""

import json
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generates detailed incident reports from simulation results."""

    def __init__(self):
        self.report_data = {}

    def generate_report(
        self,
        scenario: dict,
        environment: dict,
        alerts: list,
        incidents: list,
        mitre_coverage: dict,
        scores: dict,
        logs_stats: dict,
        timeline: list,
    ) -> dict:
        """Generate a complete incident report."""
        now = datetime.now()

        self.report_data = {
            "report_id": f"RPT-{now.strftime('%Y%m%d-%H%M%S')}",
            "generated_at": now.isoformat(),
            "title": f"CyberTwin SOC - Incident Report: {scenario.get('name', 'Unknown')}",
            "executive_summary": self._build_executive_summary(scenario, scores, alerts, incidents),
            "scenario_overview": self._build_scenario_overview(scenario),
            "environment_summary": self._build_environment_summary(environment),
            "incident_timeline": self._build_timeline_section(timeline),
            "alerts_summary": self._build_alerts_summary(alerts),
            "incidents_summary": self._build_incidents_summary(incidents),
            "mitre_attack_coverage": self._build_mitre_section(mitre_coverage, scenario),
            "detection_analysis": self._build_detection_analysis(scenario, alerts, scores),
            "scoring": scores,
            "risk_assessment": self._build_risk_assessment(scores, environment),
            "recommendations": self._build_recommendations(scores, mitre_coverage, alerts, scenario),
            "telemetry_statistics": logs_stats,
            "conclusion": self._build_conclusion(scores),
        }

        return self.report_data

    def _build_executive_summary(self, scenario: dict, scores: dict, alerts: list, incidents: list) -> dict:
        """Build the executive summary section."""
        overall = scores.get("overall_score", 0)
        risk = scores.get("risk_level", "Unknown")

        if overall >= 80:
            assessment = "The SOC demonstrated strong defensive capabilities with comprehensive detection coverage."
        elif overall >= 60:
            assessment = "The SOC showed moderate detection capabilities with notable gaps requiring attention."
        elif overall >= 40:
            assessment = "The SOC exhibited significant detection gaps that expose the organization to substantial risk."
        else:
            assessment = "The SOC has critical deficiencies in detection capabilities requiring immediate remediation."

        return {
            "scenario_name": scenario.get("name", "Unknown"),
            "scenario_severity": scenario.get("severity", "Unknown"),
            "total_attack_phases": len(scenario.get("phases", [])),
            "total_alerts_generated": len(alerts),
            "total_incidents_correlated": len(incidents),
            "overall_score": overall,
            "risk_level": risk,
            "assessment": assessment,
        }

    def _build_scenario_overview(self, scenario: dict) -> dict:
        """Build scenario overview section."""
        phases = scenario.get("phases", [])
        return {
            "id": scenario.get("id", ""),
            "name": scenario.get("name", ""),
            "description": scenario.get("description", ""),
            "severity": scenario.get("severity", ""),
            "category": scenario.get("category", ""),
            "total_phases": len(phases),
            "kill_chain": scenario.get("kill_chain", []),
            "techniques_used": scenario.get("mitre_techniques_summary", []),
            "phases_detail": [
                {
                    "phase": p.get("phase"),
                    "name": p.get("name"),
                    "technique_id": p.get("technique_id"),
                    "technique_name": p.get("technique_name"),
                    "tactic": p.get("tactic"),
                    "target_host": p.get("target_host"),
                    "stealth_level": p.get("stealth_level"),
                }
                for p in phases
            ],
        }

    def _build_environment_summary(self, environment: dict) -> dict:
        """Build environment summary section."""
        hosts = environment.get("hosts", [])
        return {
            "network_name": environment.get("network", {}).get("name", ""),
            "total_hosts": len(hosts),
            "host_types": self._count_by_key(hosts, "type"),
            "critical_assets": [h["hostname"] for h in hosts if h.get("criticality") == "critical"],
            "high_value_assets": [h["hostname"] for h in hosts if h.get("criticality") in ("critical", "high")],
        }

    def _build_timeline_section(self, timeline: list) -> list:
        """Build incident timeline section."""
        return sorted(timeline, key=lambda x: x.get("timestamp", ""))[:100]

    def _build_alerts_summary(self, alerts: list) -> dict:
        """Build alerts summary section."""
        return {
            "total_alerts": len(alerts),
            "by_severity": self._count_by_key(alerts, "severity"),
            "by_tactic": self._count_by_key(alerts, "tactic"),
            "affected_hosts": list(set(a.get("affected_host", "") for a in alerts if a.get("affected_host"))),
            "affected_users": list(set(a.get("affected_user", "") for a in alerts if a.get("affected_user"))),
            "alerts_detail": [
                {
                    "alert_id": a.get("alert_id"),
                    "rule_name": a.get("rule_name"),
                    "severity": a.get("severity"),
                    "timestamp": a.get("timestamp"),
                    "description": a.get("description"),
                    "technique_id": a.get("technique_id"),
                    "affected_host": a.get("affected_host"),
                }
                for a in alerts[:50]
            ],
        }

    def _build_incidents_summary(self, incidents: list) -> dict:
        """Build incidents summary section."""
        return {
            "total_incidents": len(incidents),
            "incidents": [
                {
                    "incident_id": inc.get("incident_id"),
                    "name": inc.get("name"),
                    "severity": inc.get("severity"),
                    "confidence_score": inc.get("confidence_score"),
                    "alert_count": len(inc.get("alerts", [])),
                    "affected_hosts": inc.get("affected_hosts", []),
                    "techniques": inc.get("techniques", []),
                    "kill_chain_phases": inc.get("kill_chain_phase", []),
                }
                for inc in incidents
            ],
        }

    def _build_mitre_section(self, mitre_coverage: dict, scenario: dict) -> dict:
        """Build MITRE ATT&CK section."""
        expected = set(scenario.get("mitre_techniques_summary", []))
        detected = set()
        for techniques in mitre_coverage.get("coverage_matrix", {}).values():
            for t in techniques:
                detected.add(t if isinstance(t, str) else t.get("technique_id", ""))

        detected_from_expected = set()
        for exp in expected:
            if any(self._technique_matches(exp, d) for d in detected):
                detected_from_expected.add(exp)
        missed = expected - detected_from_expected

        return {
            "expected_techniques": list(expected),
            "detected_techniques": list(detected_from_expected),
            "missed_techniques": list(missed),
            "coverage_percentage": round(len(detected_from_expected) / len(expected) * 100, 1) if expected else 0,
            "heatmap": mitre_coverage.get("heatmap", {}),
            "coverage_matrix": mitre_coverage.get("coverage_matrix", {}),
        }

    def _build_detection_analysis(self, scenario: dict, alerts: list, scores: dict) -> dict:
        """Build detection analysis section."""
        phases = scenario.get("phases", [])
        expected_detections = scenario.get("expected_detection_points", [])
        actual_detections = [a.get("rule_name", "") for a in alerts]

        phase_detection = []
        for phase in phases:
            ptid = phase.get("technique_id", "")
            phase_alerts = [a for a in alerts if self._technique_matches(ptid, a.get("technique_id", ""))]
            phase_detection.append({
                "phase": phase.get("phase"),
                "name": phase.get("name"),
                "technique_id": phase.get("technique_id"),
                "detected": len(phase_alerts) > 0,
                "alert_count": len(phase_alerts),
                "stealth_level": phase.get("stealth_level"),
            })

        detected_count = sum(1 for p in phase_detection if p["detected"])

        return {
            "total_phases": len(phases),
            "phases_detected": detected_count,
            "phases_missed": len(phases) - detected_count,
            "detection_rate": round(detected_count / len(phases) * 100, 1) if phases else 0,
            "expected_detection_points": expected_detections,
            "actual_detections": actual_detections,
            "phase_by_phase": phase_detection,
            "mean_time_to_detect_seconds": scores.get("details", {}).get("mean_time_to_detect", None),
        }

    def _build_risk_assessment(self, scores: dict, environment: dict) -> dict:
        """Build risk assessment section."""
        overall = scores.get("overall_score", 0)
        hosts = environment.get("hosts", [])

        if overall >= 80:
            posture = "Strong"
            description = "The organization demonstrates a mature security posture with comprehensive monitoring."
        elif overall >= 60:
            posture = "Moderate"
            description = "The security posture is adequate but has gaps that could be exploited by determined attackers."
        elif overall >= 40:
            posture = "Weak"
            description = "Significant security gaps exist that leave the organization vulnerable to common attack techniques."
        else:
            posture = "Critical"
            description = "The security posture is critically deficient and requires immediate attention."

        critical_assets = [h for h in hosts if h.get("criticality") in ("critical", "high")]

        return {
            "security_posture": posture,
            "posture_description": description,
            "overall_risk_score": 100 - overall,
            "critical_assets_at_risk": [h.get("hostname") for h in critical_assets],
            "maturity_level": scores.get("maturity_level", "Unknown"),
        }

    def _build_recommendations(self, scores: dict, mitre_coverage: dict, alerts: list, scenario: dict) -> list:
        """Build actionable recommendations based on analysis."""
        recommendations = []
        existing_recs = scores.get("recommendations", [])
        recommendations.extend(existing_recs)

        detection_score = scores.get("detection_score", 0)
        coverage_score = scores.get("coverage_score", 0)
        visibility_score = scores.get("visibility_score", 0)

        if detection_score < 50:
            recommendations.append({
                "priority": "critical",
                "category": "Detection Rules",
                "title": "Implement additional detection rules",
                "description": "The current detection rules missed a significant portion of attack phases. Review and implement rules for the missed techniques.",
            })

        if coverage_score < 60:
            recommendations.append({
                "priority": "high",
                "category": "MITRE Coverage",
                "title": "Expand MITRE ATT&CK coverage",
                "description": "Several MITRE ATT&CK techniques used in this scenario were not covered by detection rules.",
            })

        if visibility_score < 60:
            recommendations.append({
                "priority": "high",
                "category": "Logging",
                "title": "Improve log collection and visibility",
                "description": "Enhance logging coverage across all assets to ensure security events are captured.",
            })

        if not any(a.get("severity") == "critical" for a in alerts):
            recommendations.append({
                "priority": "medium",
                "category": "Alert Tuning",
                "title": "Review alert severity classification",
                "description": "No critical-severity alerts were generated during this attack simulation. Review severity thresholds.",
            })

        return recommendations

    def _build_conclusion(self, scores: dict) -> str:
        """Build the conclusion text."""
        overall = scores.get("overall_score", 0)
        risk = scores.get("risk_level", "Unknown")
        maturity = scores.get("maturity_level", "Unknown")

        return (
            f"This simulation assessment resulted in an overall security score of {overall}/100, "
            f"indicating a {risk} risk level with a maturity level of '{maturity}'. "
            f"The detection score was {scores.get('detection_score', 0)}/100, "
            f"MITRE coverage score was {scores.get('coverage_score', 0)}/100, "
            f"and visibility score was {scores.get('visibility_score', 0)}/100. "
            f"Organizations should address the identified gaps and implement the recommended improvements "
            f"to strengthen their defensive posture."
        )

    @staticmethod
    def _technique_matches(phase_tid: str, alert_tid: str) -> bool:
        """Check if techniques match including parent-child."""
        if not phase_tid or not alert_tid:
            return False
        if phase_tid == alert_tid:
            return True
        return phase_tid.split(".")[0] == alert_tid.split(".")[0]

    def _count_by_key(self, items: list, key: str) -> dict:
        """Count items grouped by a specific key."""
        counts = {}
        for item in items:
            val = item.get(key, "unknown")
            if isinstance(val, str):
                counts[val] = counts.get(val, 0) + 1
        return counts

    def export_json(self, output_path: str = None) -> str:
        """Export report as JSON."""
        json_str = json.dumps(self.report_data, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(json_str, encoding="utf-8")
        return json_str

    def export_summary(self) -> str:
        """Export a human-readable summary."""
        if not self.report_data:
            return "No report data available."

        summary = self.report_data.get("executive_summary", {})
        scores = self.report_data.get("scoring", {})
        detection = self.report_data.get("detection_analysis", {})
        mitre = self.report_data.get("mitre_attack_coverage", {})

        lines = [
            "=" * 70,
            "  CYBERTWIN SOC - INCIDENT REPORT",
            f"  {self.report_data.get('title', '')}",
            "=" * 70,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"  Scenario: {summary.get('scenario_name', '')}",
            f"  Severity: {summary.get('scenario_severity', '')}",
            f"  Attack Phases: {summary.get('total_attack_phases', 0)}",
            f"  Alerts Generated: {summary.get('total_alerts_generated', 0)}",
            f"  Incidents Correlated: {summary.get('total_incidents_correlated', 0)}",
            "",
            f"  Overall Score: {summary.get('overall_score', 0)}/100",
            f"  Risk Level: {summary.get('risk_level', '')}",
            f"  Assessment: {summary.get('assessment', '')}",
            "",
            "DETECTION ANALYSIS",
            "-" * 40,
            f"  Phases Detected: {detection.get('phases_detected', 0)}/{detection.get('total_phases', 0)}",
            f"  Detection Rate: {detection.get('detection_rate', 0)}%",
            "",
            "MITRE ATT&CK COVERAGE",
            "-" * 40,
            f"  Expected Techniques: {len(mitre.get('expected_techniques', []))}",
            f"  Detected Techniques: {len(mitre.get('detected_techniques', []))}",
            f"  Missed Techniques: {len(mitre.get('missed_techniques', []))}",
            f"  Coverage: {mitre.get('coverage_percentage', 0)}%",
            "",
            "SCORES",
            "-" * 40,
            f"  Detection Score: {scores.get('detection_score', 0)}/100",
            f"  MITRE Coverage: {scores.get('coverage_score', 0)}/100",
            f"  Response Score: {scores.get('response_score', 0)}/100",
            f"  Visibility Score: {scores.get('visibility_score', 0)}/100",
            f"  Maturity Level: {scores.get('maturity_level', '')}",
            "",
            "=" * 70,
        ]

        return "\n".join(lines)
