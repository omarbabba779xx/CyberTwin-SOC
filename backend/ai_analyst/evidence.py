"""Evidence-first analysis output (Phase 3 - structured output)."""

from __future__ import annotations

import re
from typing import Any


class EvidenceMixin:
    """``analyse_with_evidence`` and its strict-grounding helpers."""

    # Patterns we mask before exposing event values
    _SECRET_PATTERNS = [
        re.compile(r"(password|passwd|pwd|token|apikey|api_key|secret)\s*[=:]\s*\S+",
                   re.IGNORECASE),
        re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9]{32,}\b"),   # generic long hex/base64
    ]

    def analyse_with_evidence(
        self,
        scenario: dict[str, Any],
        alerts: list[dict[str, Any]],
        incidents: list[dict[str, Any]],
        scores: dict[str, Any],
        mitre_coverage: dict[str, Any],
        timeline: list[dict[str, Any]],
        logs_stats: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a STRICTLY-STRUCTURED evidence-first analysis.

        Rules enforced by this method:
          - Every conclusion in `summary` must be grounded in at least one
            entry of `evidence`. If no alert was raised, the summary
            explicitly states the absence of evidence.
          - Never invents an IOC: only IOCs already present in the alerts
            or scenario indicators are returned.
          - Never invents APT / threat-actor attribution. The platform is
            *not* a threat-intel oracle.
          - Always lists `limitations` so consumers know what was missing.
          - Strips obvious secrets/PII (API keys, tokens, password=...) from
            the values shown in `evidence` before returning.
        """
        evidence_items = self._collect_evidence(alerts, timeline)
        mitre_techniques = sorted({
            a.get("technique_id") for a in alerts
            if a.get("technique_id")
        })

        if not alerts:
            confidence = 0.0
        else:
            tactic_div = len({a.get("tactic") for a in alerts if a.get("tactic")})
            confidence = min(0.98, 0.30 + min(len(alerts), 10) * 0.05
                             + tactic_div * 0.04)

        hypotheses: list[str] = []
        if alerts and confidence < 0.6:
            hypotheses.append(
                "Activity *may* indicate "
                f"{self._classify_scenario(scenario).replace('_', ' ')}, "
                "but the evidence is too thin to conclude."
            )
            if logs_stats.get("total_events", 0) < 100:
                hypotheses.append(
                    "Low event volume — additional telemetry could change the verdict."
                )

        recommended_actions = self._evidence_grounded_actions(alerts, incidents)

        limitations: list[str] = []
        if not alerts:
            limitations.append("No alerts were raised in this run.")
        if logs_stats.get("total_events", 0) == 0:
            limitations.append("No log events ingested.")
        if not mitre_techniques:
            limitations.append("No MITRE technique mapping available on alerts.")
        for required in ("endpoint_process", "windows_event"):
            present = any(required in (e.get("event_type") or "")
                          for e in (timeline or [])[:200])
            if not present:
                limitations.append(f"No '{required}' telemetry was observed.")

        if alerts:
            summary = (
                f"{len(alerts)} alert(s) were raised across "
                f"{len({a.get('tactic') for a in alerts})} MITRE tactic(s). "
                f"All conclusions below are grounded in the listed evidence "
                f"(no IOCs or attribution are inferred beyond the data)."
            )
        else:
            summary = (
                "No alerts were raised. The detection pipeline did not match "
                "any rule; this is *not* a guarantee that the environment is clean."
            )

        iocs = self._extract_iocs(scenario, alerts, timeline)

        return {
            "schema_version": "1.0",
            "summary": summary,
            "confidence": round(confidence, 2),
            "evidence": evidence_items[:50],
            "mitre": mitre_techniques,
            "hypotheses": hypotheses,
            "recommended_actions": recommended_actions[:10],
            "iocs": {k: sorted(set(v))[:25] for k, v in iocs.items()},
            "limitations": limitations,
            "guardrails": [
                "no_fabricated_iocs",
                "no_apt_attribution",
                "every_claim_cites_evidence",
                "secrets_pii_masked",
            ],
        }

    @classmethod
    def _mask_secrets(cls, value: Any) -> str:
        s = str(value or "")
        for pat in cls._SECRET_PATTERNS:
            s = pat.sub("[REDACTED]", s)
        if len(s) > 240:
            s = s[:237] + "..."
        return s

    @classmethod
    def _collect_evidence(
        cls, alerts: list[dict], timeline: list[dict],
    ) -> list[dict[str, Any]]:
        """Build the structured `evidence` list strictly from real events."""
        out: list[dict[str, Any]] = []
        for alert in alerts:
            rule = alert.get("rule_id", "")
            for ev in alert.get("matched_events", []) or []:
                for field, label in (
                    ("command_line", "process.command_line"),
                    ("process_name", "process.name"),
                    ("description", "event.description"),
                    ("query", "dns.query"),
                    ("dest_ip", "network.dest_ip"),
                    ("file_path", "file.path"),
                    ("user", "user.name"),
                ):
                    if ev.get(field):
                        out.append({
                            "event_id": ev.get("event_id", ""),
                            "field": label,
                            "value": cls._mask_secrets(ev.get(field)),
                            "matched_rule": rule,
                            "reason": alert.get("rule_name", ""),
                            "timestamp": ev.get("timestamp", ""),
                        })
                        break
        return out

    @staticmethod
    def _evidence_grounded_actions(
        alerts: list[dict], incidents: list[dict],
    ) -> list[str]:
        """Produce recommended actions tied to specific alert IDs."""
        actions: list[str] = []
        seen: set[str] = set()
        for inc in incidents[:5]:
            iid = inc.get("incident_id")
            sev = inc.get("severity", "medium")
            hosts = inc.get("affected_hosts", [])
            if iid and iid not in seen:
                actions.append(
                    f"Investigate incident {iid} ({sev}) "
                    f"— affected hosts: {', '.join(hosts[:3]) or 'n/a'}."
                )
                seen.add(iid)
        for alert in alerts[:5]:
            aid = alert.get("alert_id", "")
            if aid and aid not in seen:
                actions.append(
                    f"Validate alert {aid} ({alert.get('rule_id', '?')}): "
                    f"{alert.get('rule_name', '')[:80]}."
                )
                seen.add(aid)
        if not actions:
            actions.append(
                "No alerts to action. Verify that telemetry sources are "
                "actually emitting events (check ingestion stats)."
            )
        return actions
