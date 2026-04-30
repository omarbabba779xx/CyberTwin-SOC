"""``AIAnalyst`` class — orchestrator that ties the analysis mixins together."""

from __future__ import annotations

from typing import Any

from .evidence import EvidenceMixin
from .extractors import ExtractorMixin
from .narrative import NarrativeMixin
from .recommendations import RecommendationsMixin
from .reporting import ReportingMixin


class AIAnalyst(
    EvidenceMixin,
    ExtractorMixin,
    NarrativeMixin,
    RecommendationsMixin,
    ReportingMixin,
):
    """Produces analyst-quality incident narratives using rule-based NLG.

    All generation is deterministic and local — no external LLM API is called.

    Usage::

        analyst = AIAnalyst()
        analysis = analyst.analyse_incident(
            scenario=scenario_dict,
            alerts=alerts_list,
            incidents=incidents_list,
            scores=scores_dict,
            mitre_coverage=mitre_dict,
            timeline=timeline_list,
            logs_stats=logs_stats_dict,
        )

    Implementation lives across topical mixins in this package:
      * ``evidence``         — strict evidence-grounded output
      * ``extractors``       — scenario classification + IOC/host/user/tactic extraction
      * ``narrative``        — executive narrative + attack chain + threat assessment
      * ``recommendations``  — detection gaps + immediate actions + strategic advice
      * ``reporting``        — affected assets + compliance impact + confidence + timestamps
    """

    def analyse_incident(
        self,
        scenario: dict[str, Any],
        alerts: list[dict[str, Any]],
        incidents: list[dict[str, Any]],
        scores: dict[str, Any],
        mitre_coverage: dict[str, Any],
        timeline: list[dict[str, Any]],
        logs_stats: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a comprehensive AI-generated analysis dict."""

        scenario_type = self._classify_scenario(scenario)
        severity = scenario.get("severity", "medium")
        detection_rate = self._detection_rate_band(scores)
        affected_hosts = self._extract_affected_hosts(alerts, timeline)
        affected_users = self._extract_affected_users(alerts, timeline)
        tactics_observed = self._extract_tactics(scenario, alerts)
        iocs = self._extract_iocs(scenario, alerts, timeline)
        phases = scenario.get("phases", [])

        return {
            "executive_narrative": self._build_executive_narrative(
                scenario, scenario_type, severity, detection_rate,
                alerts, incidents, scores, affected_hosts, affected_users,
                tactics_observed, timeline, logs_stats, phases,
            ),
            "attack_chain_summary": self._build_attack_chain(
                scenario, phases, alerts, timeline, affected_hosts,
            ),
            "threat_assessment": self._build_threat_assessment(
                scenario, severity, scores, detection_rate,
                affected_hosts, incidents,
            ),
            "detection_gaps": self._build_detection_gaps(
                scenario, scores, alerts, phases, mitre_coverage,
            ),
            "immediate_actions": self._build_immediate_actions(
                scenario_type, severity, affected_hosts, affected_users,
                iocs, incidents,
            ),
            "strategic_recommendations": self._build_strategic_recommendations(
                scenario_type, scores, mitre_coverage, detection_rate,
                logs_stats,
            ),
            "ioc_summary": iocs,
            "affected_assets_analysis": self._build_affected_assets(
                affected_hosts, alerts, incidents, timeline,
            ),
            "compliance_impact": self._build_compliance_impact(
                scenario_type, severity, scores, affected_hosts,
                affected_users, iocs,
            ),
            "analyst_confidence": self._build_confidence(
                scores, alerts, incidents, logs_stats, timeline,
            ),
        }
