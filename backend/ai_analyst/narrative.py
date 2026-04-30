"""Executive narrative, attack chain summary, and threat assessment."""

from __future__ import annotations

from typing import Any


class NarrativeMixin:
    """Builds the prose-style sections of the analyst output."""

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
