"""
CyberTwin SOC - AI Analyst Module

Rule-based Natural Language Generation engine that produces professional,
analyst-quality incident reports without requiring any external API.

The AIAnalyst class examines simulation artefacts (alerts, incidents, scores,
MITRE coverage, timeline, logs) and generates a comprehensive analysis dict
that reads as if a Level 3 SOC analyst wrote it.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Scenario-type classifier keywords
# ---------------------------------------------------------------------------

_SCENARIO_KEYWORDS: dict[str, list[str]] = {
    "phishing": ["phishing", "spear", "email", "credential_harvest", "lure"],
    "brute_force": ["brute", "password_guess", "credential_access", "spray"],
    "lateral_movement": ["lateral", "pivot", "remote_service", "ssh", "rdp", "smb"],
    "exfiltration": ["exfil", "staging", "archive", "data_theft", "cloud_storage"],
}

_TACTIC_VERB: dict[str, str] = {
    "Initial Access": "gained initial access",
    "Execution": "executed malicious code",
    "Persistence": "established persistence",
    "Privilege Escalation": "escalated privileges",
    "Defense Evasion": "evaded defensive controls",
    "Credential Access": "harvested credentials",
    "Discovery": "performed internal reconnaissance",
    "Lateral Movement": "moved laterally across the network",
    "Collection": "collected sensitive data",
    "Command and Control": "established command-and-control communications",
    "Exfiltration": "exfiltrated data from the environment",
    "Impact": "executed destructive or disruptive actions",
    "Reconnaissance": "conducted external reconnaissance",
    "Resource Development": "developed operational resources",
}


class AIAnalyst:
    """Produces analyst-quality incident narratives using rule-based NLG.

    All generation is deterministic and local -- no external LLM API is called.

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
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Scenario classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_scenario(scenario: dict) -> str:
        blob = " ".join([
            scenario.get("id", ""),
            scenario.get("name", ""),
            scenario.get("description", ""),
            scenario.get("category", ""),
        ]).lower()
        best, best_score = "unknown", 0
        for stype, keywords in _SCENARIO_KEYWORDS.items():
            hits = sum(1 for kw in keywords if kw in blob)
            if hits > best_score:
                best, best_score = stype, hits
        return best

    @staticmethod
    def _detection_rate_band(scores: dict) -> str:
        det = scores.get("detection_score", 0)
        if det >= 75:
            return "high"
        if det >= 40:
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Data extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_affected_hosts(
        alerts: list[dict], timeline: list[dict],
    ) -> list[str]:
        hosts: set[str] = set()
        for a in alerts:
            h = a.get("affected_host") or a.get("src_host")
            if h:
                hosts.add(h)
        for t in timeline:
            if t.get("is_malicious") and t.get("src_host"):
                hosts.add(t["src_host"])
        return sorted(hosts)

    @staticmethod
    def _extract_affected_users(
        alerts: list[dict], timeline: list[dict],
    ) -> list[str]:
        users: set[str] = set()
        for a in alerts:
            u = a.get("affected_user") or a.get("user")
            if u:
                users.add(u)
        for t in timeline:
            if t.get("is_malicious") and t.get("user"):
                users.add(t["user"])
        return sorted(users)

    @staticmethod
    def _extract_tactics(scenario: dict, alerts: list[dict]) -> list[str]:
        tactics: list[str] = []
        seen: set[str] = set()
        for p in scenario.get("phases", []):
            t = p.get("tactic", "")
            if t and t not in seen:
                tactics.append(t)
                seen.add(t)
        for a in alerts:
            t = a.get("tactic", "")
            if t and t not in seen:
                tactics.append(t)
                seen.add(t)
        return tactics

    @staticmethod
    def _extract_iocs(
        scenario: dict, alerts: list[dict], timeline: list[dict],
    ) -> dict[str, list[str]]:
        ips: set[str] = set()
        domains: set[str] = set()
        hashes: set[str] = set()
        accounts: set[str] = set()
        emails: set[str] = set()
        urls: set[str] = set()

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_re = re.compile(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b")
        hash_re = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
        email_re = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")

        # Scan phases for IOCs in indicators dict
        for phase in scenario.get("phases", []):
            indicators = phase.get("indicators", {})
            for key, val in indicators.items():
                if not isinstance(val, str):
                    continue
                if "ip" in key.lower():
                    ips.add(val)
                if "domain" in key.lower():
                    domains.add(val)
                if "url" in key.lower():
                    urls.add(val)
                if "sender" in key.lower() or "email" in key.lower():
                    emails.add(val)
                if "hash" in key.lower():
                    hashes.add(val)

            target_user = phase.get("target_user")
            if target_user:
                accounts.add(target_user)

        # Scan alerts descriptions
        for a in alerts:
            desc = a.get("description", "")
            ips.update(ip_re.findall(desc))
            domains.update(d for d in domain_re.findall(desc) if "." in d and not d[0].isdigit())

        # Scan malicious timeline entries
        for t in timeline:
            if not t.get("is_malicious"):
                continue
            desc = t.get("description", "")
            ips.update(ip_re.findall(desc))
            if t.get("user"):
                accounts.add(t["user"])

        # Remove obviously internal/private IPs from IOC list (keep them separately)
        external_ips = {ip for ip in ips if not _is_private_ip(ip)}
        internal_ips = {ip for ip in ips if _is_private_ip(ip)}

        return {
            "external_ips": sorted(external_ips),
            "internal_ips": sorted(internal_ips),
            "domains": sorted(domains),
            "urls": sorted(urls),
            "file_hashes": sorted(hashes),
            "compromised_accounts": sorted(accounts),
            "email_addresses": sorted(emails),
        }

    # ------------------------------------------------------------------
    # Executive Narrative
    # ------------------------------------------------------------------

    def _build_executive_narrative(
        self,
        scenario: dict,
        scenario_type: str,
        severity: str,
        detection_rate: str,
        alerts: list[dict],
        incidents: list[dict],
        scores: dict,
        affected_hosts: list[str],
        affected_users: list[str],
        tactics_observed: list[str],
        timeline: list[dict],
        logs_stats: dict,
        phases: list[dict],
    ) -> str:
        name = scenario.get("name", "Unknown Incident")
        overall = scores.get("overall_score", 0)
        risk = scores.get("risk_level", "Unknown")
        n_phases = len(phases)
        n_alerts = len(alerts)
        n_incidents = len(incidents)

        # -- Paragraph 1: Incident overview
        hosts_str = ", ".join(affected_hosts[:5]) if affected_hosts else "multiple hosts"
        users_str = ", ".join(affected_users[:3]) if affected_users else "several user accounts"

        malicious_events = [t for t in timeline if t.get("is_malicious")]
        first_ts = malicious_events[0].get("timestamp", "") if malicious_events else "N/A"
        last_ts = malicious_events[-1].get("timestamp", "") if malicious_events else "N/A"

        p1 = (
            f"On {self._format_ts(first_ts)}, CyberTwin SOC simulation detected activity "
            f"consistent with a {name} targeting the organization's infrastructure. "
            f"The attack campaign, classified as {severity.upper()} severity, "
            f"progressed through {n_phases} distinct phases spanning from "
            f"{self._format_ts(first_ts)} to {self._format_ts(last_ts)}. "
            f"Primary targets included hosts {hosts_str}, with compromised or targeted "
            f"user accounts including {users_str}."
        )

        # -- Paragraph 2: Attack progression (scenario-type-specific)
        p2 = self._narrative_attack_progression(
            scenario_type, phases, tactics_observed, affected_hosts, affected_users,
        )

        # -- Paragraph 3: Detection performance
        det_score = scores.get("detection_score", 0)
        cov_score = scores.get("coverage_score", 0)
        missed_tech = scores.get("details", {}).get("techniques_missed", [])
        mttd = scores.get("details", {}).get("mean_time_to_detect")

        if detection_rate == "high":
            det_assessment = (
                f"The SOC demonstrated strong detection performance, achieving a "
                f"detection score of {det_score}% with {n_alerts} alerts generated "
                f"across {n_incidents} correlated incident(s). "
                f"MITRE ATT&CK coverage reached {cov_score}%, indicating mature "
                f"rule coverage across the observed tactics."
            )
        elif detection_rate == "medium":
            det_assessment = (
                f"Detection performance was moderate with a detection score of {det_score}%. "
                f"The detection engine generated {n_alerts} alert(s) and correlated "
                f"{n_incidents} incident(s), but MITRE ATT&CK coverage of {cov_score}% "
                f"reveals gaps in technique-level detection. "
                f"Missed techniques include: {', '.join(missed_tech[:5]) if missed_tech else 'none identified'}."
            )
        else:
            det_assessment = (
                f"Detection capabilities showed significant deficiencies with a "
                f"detection score of only {det_score}%. Only {n_alerts} alert(s) were "
                f"generated across {n_incidents} incident(s), and MITRE ATT&CK coverage "
                f"was limited to {cov_score}%. Multiple attack phases progressed "
                f"undetected, including techniques: "
                f"{', '.join(missed_tech[:5]) if missed_tech else 'several critical techniques'}."
            )

        if mttd is not None:
            det_assessment += (
                f" Mean time to detect (MTTD) was measured at {mttd:.0f} seconds "
                f"({mttd / 60:.1f} minutes)."
            )

        p3 = det_assessment

        # -- Paragraph 4: Risk and business impact
        vis = scores.get("visibility_score", 0)
        total_logs = logs_stats.get("total_logs", 0)
        sources = logs_stats.get("log_sources", {})
        n_sources = len(sources) if isinstance(sources, dict) else 0

        if overall >= 75:
            risk_text = (
                f"Overall risk is assessed as {risk}. The organization's detection and "
                f"visibility capabilities (visibility score: {vis}%, across {n_sources} "
                f"log source categories, {total_logs} total log events) provide adequate "
                f"coverage to identify and respond to threats of this nature. "
                f"Continued tuning and periodic assessment are recommended."
            )
        elif overall >= 45:
            risk_text = (
                f"The residual risk following this assessment is {risk}. With a visibility "
                f"score of {vis}% across {n_sources} log source categories and {total_logs} "
                f"total events analysed, the organization has foundational monitoring in place "
                f"but lacks the depth required to reliably detect advanced multi-stage attacks. "
                f"Priority remediation of the identified detection gaps is strongly recommended."
            )
        else:
            risk_text = (
                f"The organization faces {risk} risk. Current visibility ({vis}%) and "
                f"detection capabilities are insufficient to protect against attacks of this "
                f"sophistication. With only {n_sources} log source categories active and "
                f"{total_logs} events processed, critical blind spots exist across the "
                f"attack surface. Immediate investment in detection engineering, log source "
                f"integration, and SOC capability maturation is imperative."
            )

        p4 = risk_text

        # -- Paragraph 5: Summary conclusion
        maturity = scores.get("maturity_level", "Unknown")
        p5 = (
            f"In conclusion, this simulation exercise — classified under the "
            f"'{scenario.get('category', 'general')}' category — resulted in an overall "
            f"security posture score of {overall}/100, placing the organization at "
            f"'{maturity}' maturity level. The assessment identified "
            f"{len(scores.get('details', {}).get('techniques_missed', []))} undetected "
            f"MITRE ATT&CK techniques and highlighted {len(scores.get('recommendations', []))} "
            f"actionable recommendations. Immediate containment actions should focus on the "
            f"affected assets ({', '.join(affected_hosts[:3])}) and compromised accounts "
            f"({', '.join(affected_users[:3])})."
        )

        return "\n\n".join([p1, p2, p3, p4, p5])

    def _narrative_attack_progression(
        self,
        scenario_type: str,
        phases: list[dict],
        tactics: list[str],
        hosts: list[str],
        users: list[str],
    ) -> str:
        tactic_chain = " -> ".join(tactics) if tactics else "multiple tactics"
        host0 = hosts[0] if hosts else "the initial target"
        user0 = users[0] if users else "a targeted user"

        if scenario_type == "phishing":
            return (
                f"The attack originated with a spear-phishing campaign targeting {user0} "
                f"on host {host0}. Upon successful credential harvesting, the threat actor "
                f"leveraged stolen credentials to authenticate to internal systems, "
                f"subsequently performing reconnaissance and lateral movement across the "
                f"environment. The observed kill chain followed the progression: {tactic_chain}. "
                f"This pattern is consistent with financially motivated threat groups and "
                f"advanced persistent threat (APT) actors who rely on social engineering "
                f"as their primary initial access vector."
            )

        if scenario_type == "brute_force":
            return (
                f"The attack initiated with brute-force password guessing activity against "
                f"authentication services, targeting account {user0} on host {host0}. "
                f"Following successful credential compromise, the adversary progressed through "
                f"privilege escalation and lateral movement phases. The tactical progression "
                f"observed was: {tactic_chain}. This attack pattern is characteristic of "
                f"opportunistic threat actors and automated attack toolkits that probe "
                f"exposed authentication endpoints for weak or default credentials."
            )

        if scenario_type == "lateral_movement":
            return (
                f"The attack centred on lateral movement operations, with the threat actor "
                f"pivoting across internal systems starting from {host0}. Using compromised "
                f"credentials belonging to {user0}, the adversary leveraged remote services "
                f"(SSH/RDP/SMB) to move through the environment, establishing presence on "
                f"multiple hosts: {', '.join(hosts[:4])}. The tactical chain followed: "
                f"{tactic_chain}. This behaviour is indicative of an adversary who has "
                f"already achieved initial access and is actively expanding their foothold."
            )

        if scenario_type == "exfiltration":
            return (
                f"The attack culminated in data exfiltration operations after the adversary "
                f"staged and archived sensitive data from compromised systems. Beginning with "
                f"data collection on {host0} under the context of {user0}, the threat actor "
                f"systematically identified high-value files, staged them locally, and "
                f"exfiltrated them via alternative channels. The observed tactics were: "
                f"{tactic_chain}. This pattern suggests a targeted data theft operation "
                f"consistent with corporate espionage or insider threat scenarios."
            )

        # Generic fallback
        return (
            f"The adversary executed a multi-stage attack campaign progressing through "
            f"{len(phases)} phases. Initial compromise occurred on {host0} targeting "
            f"account {user0}, after which the attack expanded across additional systems. "
            f"The tactical progression observed was: {tactic_chain}. This multi-phase "
            f"attack pattern demonstrates the adversary's operational sophistication and "
            f"persistence in achieving their objectives."
        )

    # ------------------------------------------------------------------
    # Attack chain summary
    # ------------------------------------------------------------------

    @staticmethod
    def _build_attack_chain(
        scenario: dict,
        phases: list[dict],
        alerts: list[dict],
        timeline: list[dict],
        affected_hosts: list[str],
    ) -> list[dict[str, Any]]:
        alert_techniques = {a.get("technique_id") for a in alerts if a.get("technique_id")}
        chain: list[dict[str, Any]] = []

        for phase in phases:
            ptid = phase.get("technique_id", "")
            detected = any(
                ptid.split(".")[0] == atid.split(".")[0]
                for atid in alert_techniques if atid
            ) if ptid else False

            # Find matching timeline entries
            phase_events = [
                t for t in timeline
                if t.get("is_malicious") and t.get("technique_id")
                and (t["technique_id"] == ptid or t["technique_id"].split(".")[0] == ptid.split(".")[0])
            ]
            first_event_ts = phase_events[0].get("timestamp", "") if phase_events else "N/A"

            chain.append({
                "step": phase.get("phase", 0),
                "name": phase.get("name", ""),
                "technique_id": ptid,
                "technique_name": phase.get("technique_name", ""),
                "tactic": phase.get("tactic", ""),
                "target_host": phase.get("target_host", ""),
                "target_user": phase.get("target_user", ""),
                "stealth_level": phase.get("stealth_level", "medium"),
                "detected": detected,
                "timestamp": first_event_ts,
                "description": (
                    f"{'[DETECTED] ' if detected else '[MISSED] '}"
                    f"{phase.get('description', '')} "
                    f"(Target: {phase.get('target_host', 'N/A')}, "
                    f"Technique: {ptid} - {phase.get('technique_name', '')}, "
                    f"Stealth: {phase.get('stealth_level', 'medium')})"
                ),
            })

        return chain

    # ------------------------------------------------------------------
    # Threat assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _build_threat_assessment(
        scenario: dict,
        severity: str,
        scores: dict,
        detection_rate: str,
        affected_hosts: list[str],
        incidents: list[dict],
    ) -> dict[str, Any]:
        overall = scores.get("overall_score", 0)
        risk = scores.get("risk_level", "Unknown")

        # Compute effective threat level from both scenario severity and detection gaps
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sev_num = sev_map.get(severity, 2)
        det_map = {"low": 3, "medium": 2, "high": 1}
        det_penalty = det_map.get(detection_rate, 2)
        effective_level = min(sev_num + det_penalty - 1, 4)
        level_names = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        effective_risk = level_names.get(effective_level, "Medium")

        justifications = []
        justifications.append(
            f"Scenario severity is rated {severity.upper()} with {len(scenario.get('phases', []))} "
            f"attack phases spanning multiple MITRE ATT&CK tactics."
        )
        if detection_rate == "low":
            justifications.append(
                "Detection rate is LOW, meaning the majority of attack phases progressed "
                "without generating alerts, significantly increasing the risk of undetected compromise."
            )
        elif detection_rate == "medium":
            justifications.append(
                "Detection rate is MODERATE, indicating that while some attack phases were "
                "identified, critical gaps remain that could allow adversary objectives to succeed."
            )
        else:
            justifications.append(
                "Detection rate is HIGH, demonstrating that the SOC can reliably identify "
                "the techniques employed in this attack pattern."
            )

        justifications.append(
            f"{len(affected_hosts)} host(s) were directly involved in the attack chain, "
            f"and {len(incidents)} incident(s) were correlated from the generated alerts."
        )

        return {
            "risk_level": effective_risk,
            "scenario_severity": severity,
            "overall_score": overall,
            "framework_risk_level": risk,
            "justification": " ".join(justifications),
        }

    # ------------------------------------------------------------------
    # Detection gaps
    # ------------------------------------------------------------------

    @staticmethod
    def _build_detection_gaps(
        scenario: dict,
        scores: dict,
        alerts: list[dict],
        phases: list[dict],
        mitre_coverage: dict,
    ) -> list[dict[str, str]]:
        gaps: list[dict[str, str]] = []
        details = scores.get("details", {})
        missed = details.get("techniques_missed", [])
        alert_techniques = {a.get("technique_id") for a in alerts if a.get("technique_id")}

        # Per-missed-technique gap
        for tid in missed:
            # Find the phase that used this technique
            matching_phase = next(
                (p for p in phases if p.get("technique_id") == tid),
                None,
            )
            phase_name = matching_phase.get("name", "Unknown phase") if matching_phase else "Unknown phase"
            tactic = matching_phase.get("tactic", "Unknown") if matching_phase else "Unknown"
            stealth = matching_phase.get("stealth_level", "unknown") if matching_phase else "unknown"

            gaps.append({
                "technique_id": tid,
                "phase": phase_name,
                "tactic": tactic,
                "stealth_level": stealth,
                "gap_description": (
                    f"No detection rule triggered for technique {tid} during the "
                    f"'{phase_name}' phase (tactic: {tactic}). The attack step had a "
                    f"{stealth} stealth level, which may require behavioural analytics "
                    f"or anomaly-based detection rather than signature matching."
                ),
                "remediation": (
                    f"Implement detection logic for {tid} using log correlation across "
                    f"relevant sources. Consider SIGMA rules targeting this technique "
                    f"and validate with atomic red team tests."
                ),
            })

        # Undetected phases (technique was partially matched but phase missed)
        for phase in phases:
            ptid = phase.get("technique_id", "")
            if not ptid:
                continue
            phase_detected = any(
                ptid.split(".")[0] == atid.split(".")[0]
                for atid in alert_techniques if atid
            )
            if not phase_detected and ptid not in missed:
                gaps.append({
                    "technique_id": ptid,
                    "phase": phase.get("name", ""),
                    "tactic": phase.get("tactic", ""),
                    "stealth_level": phase.get("stealth_level", "unknown"),
                    "gap_description": (
                        f"Attack phase '{phase.get('name', '')}' using technique {ptid} "
                        f"did not trigger any alerts despite log events being generated."
                    ),
                    "remediation": (
                        f"Review existing detection rules for coverage of {ptid}. "
                        f"Check if log source fidelity is sufficient and that correlation "
                        f"windows are appropriately configured."
                    ),
                })

        # Visibility gaps
        expected_sources = set(details.get("log_sources_expected", []))
        observed_sources = set(details.get("log_sources_observed", []))
        missing_sources = expected_sources - observed_sources
        if missing_sources:
            gaps.append({
                "technique_id": "N/A",
                "phase": "Telemetry Pipeline",
                "tactic": "Visibility",
                "stealth_level": "N/A",
                "gap_description": (
                    f"The following log source categories were expected but not observed: "
                    f"{', '.join(sorted(missing_sources))}. Absence of these sources reduces "
                    f"the detection engine's ability to identify adversary activity."
                ),
                "remediation": (
                    f"Onboard the missing log sources ({', '.join(sorted(missing_sources))}) "
                    f"into the SIEM pipeline. Validate data parsing and field normalization."
                ),
            })

        if not gaps:
            gaps.append({
                "technique_id": "N/A",
                "phase": "All",
                "tactic": "N/A",
                "stealth_level": "N/A",
                "gap_description": (
                    "No significant detection gaps were identified. All attack phases "
                    "were successfully detected by existing rules."
                ),
                "remediation": (
                    "Continue regular rule tuning and periodic validation against new "
                    "attack techniques."
                ),
            })

        return gaps

    # ------------------------------------------------------------------
    # Immediate actions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_immediate_actions(
        scenario_type: str,
        severity: str,
        affected_hosts: list[str],
        affected_users: list[str],
        iocs: dict[str, list[str]],
        incidents: list[dict],
    ) -> list[dict[str, str]]:
        actions: list[dict[str, str]] = []
        priority_counter = 0

        def _add(category: str, title: str, detail: str) -> None:
            nonlocal priority_counter
            priority_counter += 1
            actions.append({
                "priority": priority_counter,
                "category": category,
                "action": title,
                "detail": detail,
            })

        # --- Containment ---
        if affected_hosts:
            _add(
                "Containment",
                "Isolate affected endpoints from the network",
                f"Immediately network-isolate the following hosts to prevent further "
                f"lateral movement or data exfiltration: {', '.join(affected_hosts)}. "
                f"Use EDR network containment or VLAN quarantine.",
            )

        if affected_users:
            _add(
                "Containment",
                "Disable compromised user accounts",
                f"Force password reset and temporarily disable the following accounts "
                f"pending investigation: {', '.join(affected_users)}. Revoke all active "
                f"sessions and tokens for these accounts.",
            )

        ext_ips = iocs.get("external_ips", [])
        domains = iocs.get("domains", [])
        if ext_ips or domains:
            block_items = ext_ips + domains
            _add(
                "Containment",
                "Block malicious indicators at perimeter",
                f"Add the following IOCs to firewall, proxy, and DNS sinkhole block lists: "
                f"{', '.join(block_items[:10])}.",
            )

        # --- Eradication ---
        if scenario_type == "phishing":
            _add(
                "Eradication",
                "Remove phishing emails from all mailboxes",
                "Perform a tenant-wide mail purge to remove any copies of the phishing "
                "email from user mailboxes. Search by sender address, subject line, and "
                "embedded URLs identified in the IOC summary.",
            )

        _add(
            "Eradication",
            "Scan affected hosts for persistence mechanisms",
            f"Run full EDR/AV scans on {', '.join(affected_hosts[:5]) if affected_hosts else 'all targeted hosts'}. "
            f"Check for scheduled tasks, new services, registry run keys, and web shells "
            f"that may have been installed during the attack.",
        )

        if scenario_type in ("lateral_movement", "exfiltration"):
            _add(
                "Eradication",
                "Audit and rotate credentials on affected systems",
                "Rotate all local administrator passwords and service account credentials "
                "on compromised hosts. Verify Kerberos ticket validity and check for "
                "golden/silver ticket indicators.",
            )

        # --- Recovery ---
        _add(
            "Recovery",
            "Restore systems from known-good baselines",
            "For hosts where persistence mechanisms were confirmed, consider reimaging "
            "from a validated gold image. Restore data from backups verified to predate "
            "the compromise window.",
        )

        _add(
            "Recovery",
            "Re-enable monitored access and validate logging",
            "After eradication is confirmed, gradually reconnect isolated systems to "
            "the network with enhanced monitoring. Validate that all log sources are "
            "reporting correctly to the SIEM.",
        )

        # --- Post-Incident ---
        if severity in ("high", "critical"):
            _add(
                "Post-Incident",
                "Initiate incident notification procedures",
                "Notify the CISO, legal, and compliance teams per the incident response plan. "
                "If personal data was potentially exposed, assess data breach notification "
                "obligations under GDPR/applicable regulations.",
            )

        return actions

    # ------------------------------------------------------------------
    # Strategic recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _build_strategic_recommendations(
        scenario_type: str,
        scores: dict,
        mitre_coverage: dict,
        detection_rate: str,
        logs_stats: dict,
    ) -> list[dict[str, str]]:
        recs: list[dict[str, str]] = []

        det = scores.get("detection_score", 0)
        cov = scores.get("coverage_score", 0)
        vis = scores.get("visibility_score", 0)
        resp = scores.get("response_score", 0)

        if det < 60:
            recs.append({
                "category": "Detection Engineering",
                "recommendation": "Expand detection rule library",
                "detail": (
                    f"Current detection score ({det}%) indicates insufficient rule coverage. "
                    f"Prioritize development of detection analytics for the MITRE ATT&CK "
                    f"techniques observed in this scenario. Adopt SIGMA rules and map them "
                    f"to the SIEM platform."
                ),
                "effort": "Medium",
                "impact": "High",
            })

        if cov < 70:
            recs.append({
                "category": "MITRE ATT&CK Coverage",
                "recommendation": "Close technique coverage gaps",
                "detail": (
                    f"MITRE coverage ({cov}%) falls below the recommended 70% threshold. "
                    f"Map existing detection content against the ATT&CK matrix, identify "
                    f"gaps per tactic, and prioritize rules for techniques frequently used "
                    f"by threat actors relevant to the organization's industry."
                ),
                "effort": "High",
                "impact": "High",
            })

        if vis < 70:
            recs.append({
                "category": "Log Management",
                "recommendation": "Improve log source coverage and fidelity",
                "detail": (
                    f"Visibility score ({vis}%) indicates gaps in log collection. Ensure "
                    f"all critical asset categories (endpoints, network devices, identity "
                    f"providers, cloud workloads) are shipping normalized logs to the SIEM. "
                    f"Enable PowerShell script block logging, command-line auditing, and "
                    f"Sysmon on Windows endpoints."
                ),
                "effort": "Medium",
                "impact": "High",
            })

        if resp < 60:
            recs.append({
                "category": "Incident Response",
                "recommendation": "Reduce mean time to detect and respond",
                "detail": (
                    f"Response score ({resp}%) indicates slow detection latency. Implement "
                    f"automated triage playbooks (SOAR) to reduce analyst workload, deploy "
                    f"real-time correlation rules, and establish escalation SLAs for "
                    f"critical alert categories."
                ),
                "effort": "Medium",
                "impact": "High",
            })

        if scenario_type == "phishing":
            recs.append({
                "category": "User Awareness",
                "recommendation": "Enhance phishing awareness programme",
                "detail": (
                    "Conduct regular phishing simulation exercises and targeted training. "
                    "Deploy browser-based URL inspection tools and enforce MFA on all "
                    "externally facing authentication portals to limit credential theft impact."
                ),
                "effort": "Low",
                "impact": "Medium",
            })

        if scenario_type == "brute_force":
            recs.append({
                "category": "Access Control",
                "recommendation": "Harden authentication mechanisms",
                "detail": (
                    "Enforce account lockout policies, deploy adaptive MFA, and implement "
                    "IP-based rate limiting on authentication endpoints. Consider deploying "
                    "a UEBA solution to detect anomalous authentication patterns."
                ),
                "effort": "Low",
                "impact": "High",
            })

        if scenario_type == "exfiltration":
            recs.append({
                "category": "Data Protection",
                "recommendation": "Implement data loss prevention controls",
                "detail": (
                    "Deploy DLP solutions at network egress points and endpoints. Classify "
                    "sensitive data assets, restrict removable media usage, and monitor "
                    "outbound traffic for unusual volume or protocol anomalies."
                ),
                "effort": "High",
                "impact": "High",
            })

        recs.append({
            "category": "Continuous Improvement",
            "recommendation": "Establish regular purple team exercises",
            "detail": (
                "Schedule periodic attack simulation exercises using CyberTwin SOC to "
                "validate detection coverage, measure improvement over time, and train "
                "SOC analysts on emerging attack techniques."
            ),
            "effort": "Medium",
            "impact": "Medium",
        })

        return recs

    # ------------------------------------------------------------------
    # Affected assets analysis
    # ------------------------------------------------------------------

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

            # All incident IDs where this host appears
            related_incidents = [
                inc.get("incident_id", "")
                for inc in incidents
                if host in inc.get("affected_hosts", [])
            ]

            # Severity assessment per host
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

    # ------------------------------------------------------------------
    # Compliance impact
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Analyst confidence
    # ------------------------------------------------------------------

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

        # Data volume factor
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

        # Alert correlation factor
        if len(incidents) > 0:
            confidence += 5
            factors.append(
                f"{len(incidents)} correlated incident(s) confirm multi-stage attack pattern."
            )
        else:
            confidence -= 5
            factors.append("No correlated incidents reduces confidence in attack chain reconstruction.")

        # Detection coverage factor
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

        # Visibility factor
        vis = scores.get("visibility_score", 0)
        if vis >= 70:
            confidence += 5
            factors.append(f"Good log source visibility ({vis}%) across the environment.")
        elif vis < 40:
            confidence -= 10
            factors.append(f"Limited visibility ({vis}%) creates blind spots in the analysis.")

        # Clamp
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

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

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


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is RFC 1918 / loopback."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False
