"""Detection gaps, immediate actions, and strategic recommendations."""

from __future__ import annotations


class RecommendationsMixin:
    """Builds the action / gap / recommendation sections of the analyst output."""

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

        for tid in missed:
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
