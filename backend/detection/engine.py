"""
CyberTwin SOC - Detection Engine
==================================
Runs detection rules against log events, generates alerts, and correlates
multi-step incidents with MITRE ATT&CK mapping. Provides MITRE coverage
analysis including a tactic heatmap and technique detection summary.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any

from .rules import DETECTION_RULES, DetectionRule

logger = logging.getLogger("cybertwin.detection")

_CORRELATION_WINDOW_SECONDS = 900  # 15-minute temporal proximity window


class DetectionEngine:
    """Analyses log events, applies detection rules, and correlates incidents.

    Usage::

        engine = DetectionEngine()
        alerts = engine.analyse(log_dicts)
        incidents = engine.correlate_incidents(alerts)
    """

    def __init__(self, rules: list[DetectionRule] | None = None, load_sigma: bool = True):
        """Initialize the detection engine.

        Args:
            rules: Custom rule list. Defaults to the built-in DETECTION_RULES.
            load_sigma: If True, auto-load Sigma rules from data/sigma_rules/.
        """
        self._rules = list(rules or DETECTION_RULES)
        self._alerts: list[dict[str, Any]] = []
        self._incidents: list[dict[str, Any]] = []
        if load_sigma:
            self._load_sigma_rules()

    def _load_sigma_rules(self) -> None:
        """Auto-load any .yml Sigma rules from data/sigma_rules/."""
        from pathlib import Path
        sigma_dir = Path(__file__).resolve().parent.parent.parent / "data" / "sigma_rules"
        if not sigma_dir.exists():
            return
        try:
            from backend.detection.sigma_loader import SigmaLoader
            sigma_rules = SigmaLoader.load_directory(sigma_dir)
            existing_ids = {r.rule_id for r in self._rules}
            added = 0
            for rule in sigma_rules:
                if rule.rule_id not in existing_ids:
                    self._rules.append(rule)
                    existing_ids.add(rule.rule_id)
                    added += 1
            if added:
                logger.info("Loaded %d Sigma rules into DetectionEngine", added)
        except Exception as exc:
            logger.warning("Sigma rules loading failed: %s", exc)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyse(self, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run every enabled rule against *logs* and return generated alerts."""
        self._alerts = []

        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                matched_events = rule.condition(logs)
            except Exception as e:
                logger.warning("Rule '%s' failed: %s", rule.rule_id, e)
                continue

            if matched_events:
                alert = self._create_alert(rule, matched_events)
                self._alerts.append(alert)

        self._alerts.sort(key=lambda a: a.get("timestamp", ""))
        return list(self._alerts)

    def correlate_incidents(
        self, alerts: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Group related alerts into correlated incidents.

        Correlation is based on overlapping hosts, users, and temporal
        proximity.
        """
        source_alerts = alerts if alerts is not None else self._alerts
        if not source_alerts:
            return []

        self._incidents = []
        used: set[str] = set()

        # Sort by timestamp
        sorted_alerts = sorted(source_alerts, key=lambda a: a.get("timestamp", ""))

        for i, anchor in enumerate(sorted_alerts):
            aid = anchor.get("alert_id", "")
            if aid in used:
                continue

            group = [anchor]
            used.add(aid)

            for other in sorted_alerts[i + 1:]:
                oid = other.get("alert_id", "")
                if oid in used:
                    continue
                if self._alerts_related(anchor, other):
                    group.append(other)
                    used.add(oid)

            if len(group) >= 2:
                self._incidents.append(self._create_incident(group))

        # Also create a single-alert incident for standalone critical alerts
        for a in sorted_alerts:
            if a.get("alert_id") not in used and a.get("severity") == "critical":
                self._incidents.append(self._create_incident([a]))

        return list(self._incidents)

    # ------------------------------------------------------------------
    # MITRE coverage
    # ------------------------------------------------------------------

    def get_mitre_coverage(self) -> dict[str, Any]:
        """Return a MITRE ATT&CK coverage summary from current alerts."""
        coverage_matrix: dict[str, list[dict]] = defaultdict(list)
        heatmap: dict[str, int] = defaultdict(int)

        for alert in self._alerts:
            tactic = alert.get("tactic", "Unknown")
            technique_id = alert.get("technique_id", "")
            if technique_id:
                coverage_matrix[tactic].append({
                    "technique_id": technique_id,
                    "technique_name": alert.get("technique_name", ""),
                    "alert_count": len(alert.get("matched_events", [])),
                })
                heatmap[tactic] += 1

        return {
            "coverage_matrix": dict(coverage_matrix),
            "heatmap": dict(heatmap),
            "tactics_covered": list(coverage_matrix.keys()),
            "total_techniques_detected": len(
                {t["technique_id"] for v in coverage_matrix.values() for t in v}
            ),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _create_alert(rule: DetectionRule, events: list[dict]) -> dict[str, Any]:
        timestamps = [e.get("timestamp", "") for e in events]
        hosts = list({e.get("src_host", "") for e in events if e.get("src_host")})
        users = list({e.get("user", "") for e in events if e.get("user")})
        techniques = list({e.get("technique_id", "") for e in events if e.get("technique_id")})

        return {
            "alert_id": f"ALR-{uuid.uuid4().hex[:8].upper()}",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "tactic": rule.tactic,
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "timestamp": min(timestamps) if timestamps else "",
            "affected_host": hosts[0] if hosts else "",
            "affected_hosts": hosts,
            "affected_user": users[0] if users else "",
            "affected_users": users,
            "matched_event_count": len(events),
            "matched_events": [
                {
                    "event_id": e.get("event_id", ""),
                    "timestamp": e.get("timestamp", ""),
                    "event_type": e.get("event_type", ""),
                    "description": e.get("description", ""),
                }
                for e in events[:20]  # cap detail to 20 events
            ],
            "related_techniques": techniques,
        }

    @staticmethod
    def _alerts_related(a: dict, b: dict) -> bool:
        """Two alerts are related if they share a host/user AND occur within 15 minutes."""
        hosts_a = set(a.get("affected_hosts", []))
        hosts_b = set(b.get("affected_hosts", []))
        users_a = set(a.get("affected_users", []))
        users_b = set(b.get("affected_users", []))

        shares_entity = bool(hosts_a & hosts_b) or bool(users_a & users_b)
        if not shares_entity:
            return False

        ts_a_str = a.get("timestamp", "")
        ts_b_str = b.get("timestamp", "")
        if not ts_a_str or not ts_b_str:
            return True  # No timestamps — accept if entities match

        try:
            from datetime import datetime
            _TS_FMTS = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]
            ts_a: datetime | None = None
            ts_b: datetime | None = None
            for fmt in _TS_FMTS:
                try:
                    ts_a = datetime.strptime(ts_a_str, fmt)
                    break
                except ValueError:
                    pass
            for fmt in _TS_FMTS:
                try:
                    ts_b = datetime.strptime(ts_b_str, fmt)
                    break
                except ValueError:
                    pass
            if ts_a is None or ts_b is None:
                return True
            delta = abs((ts_b - ts_a).total_seconds())
            return delta <= _CORRELATION_WINDOW_SECONDS
        except Exception:
            return True

    @staticmethod
    def _create_incident(alerts: list[dict]) -> dict[str, Any]:
        all_hosts = list({h for a in alerts for h in a.get("affected_hosts", [])})
        all_users = list({u for a in alerts for u in a.get("affected_users", [])})
        all_techniques = list({a.get("technique_id", "") for a in alerts if a.get("technique_id")})
        all_tactics = list({a.get("tactic", "") for a in alerts if a.get("tactic")})
        severities = [a.get("severity", "low") for a in alerts]

        # Incident severity = highest alert severity
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = max(severities, key=lambda s: sev_order.get(s, 0))

        severity_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        tactic_diversity = len(all_tactics) / 14.0  # 14 ATT&CK tactics
        confidence = min(98, int(
            30
            + min(len(alerts), 10) * 5
            + tactic_diversity * 25
            + min(len(all_techniques), 8) * 3
            + (10 if max_sev == "critical" else 5 if max_sev == "high" else 0)
        ))
        return {
            "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
            "name": f"Correlated Incident — {', '.join(all_tactics[:3])}",
            "severity": max_sev,
            "confidence_score": confidence,
            "alert_count": len(alerts),
            "alerts": [a.get("alert_id") for a in alerts],
            "affected_hosts": all_hosts,
            "affected_users": all_users,
            "techniques": all_techniques,
            "kill_chain_phase": all_tactics,
            "timestamp_first": min(a.get("timestamp", "") for a in alerts),
            "timestamp_last": max(a.get("timestamp", "") for a in alerts),
        }
