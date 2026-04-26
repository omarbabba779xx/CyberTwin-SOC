"""
GapAnalyzer
===========
Turns TechniqueCoverage records that represent gaps into actionable
recommendations with a deterministic priority. Used by /api/coverage/gaps
and the frontend Coverage Center.
"""

from __future__ import annotations

from typing import Iterable

from .models import (
    HIGH_RISK_TACTICS,
    Gap,
    TechniqueCoverage,
    TechniqueStatus,
)


# Risk tier per (tactic, status). Lower priority number = higher urgency.
_BASE_RISK: dict[TechniqueStatus, str] = {
    TechniqueStatus.NOT_COVERED:         "high",
    TechniqueStatus.NEEDS_DATA_SOURCE:   "high",
    TechniqueStatus.RULE_UNTESTED:       "medium",
    TechniqueStatus.RULE_EXISTS:         "medium",
    TechniqueStatus.TESTED_FAILED:       "critical",
    TechniqueStatus.NOISY:               "medium",
}


def _risk_for(tc: TechniqueCoverage) -> str:
    base = _BASE_RISK.get(tc.status, "low")
    if tc.tactic_id in HIGH_RISK_TACTICS:
        # Bump one level up for high-risk tactics, capped at "critical".
        order = ["low", "medium", "high", "critical"]
        if base in order:
            return order[min(len(order) - 1, order.index(base) + 1)]
    return base


_RISK_PRIORITY = {"critical": 1, "high": 2, "medium": 3, "low": 4}


def _build_reasons(tc: TechniqueCoverage) -> list[str]:
    reasons: list[str] = []
    if tc.status is TechniqueStatus.NOT_COVERED:
        reasons.append("No detection rule references this technique.")
        if not tc.scenarios:
            reasons.append("No attack scenario exercises this technique.")
    elif tc.status is TechniqueStatus.RULE_EXISTS:
        reasons.append("Rule exists but no attack scenario exercises this technique.")
    elif tc.status is TechniqueStatus.RULE_UNTESTED:
        reasons.append("Rule and scenario exist but no recent simulation has validated detection.")
    elif tc.status is TechniqueStatus.TESTED_FAILED:
        reasons.append("Last simulation covered this technique but no rule fired.")
    elif tc.status is TechniqueStatus.NEEDS_DATA_SOURCE:
        reasons.append("Required telemetry sources are not currently available.")
    if tc.missing_logs:
        reasons.append(
            "Missing log sources: " + ", ".join(tc.missing_logs)
        )
    return reasons


def _build_recommendations(tc: TechniqueCoverage) -> list[str]:
    recs: list[str] = []

    if tc.status in {TechniqueStatus.NOT_COVERED, TechniqueStatus.RULE_EXISTS}:
        recs.append(f"Author or import a Sigma rule mapped to {tc.technique_id}.")
        recs.append(
            f"Add an attack scenario step that emits {tc.technique_id} telemetry "
            f"so the rule can be validated."
        )

    if tc.status is TechniqueStatus.RULE_UNTESTED:
        recs.append(
            f"Run an end-to-end simulation of a scenario that covers "
            f"{tc.technique_id} and verify the rule fires."
        )

    if tc.status is TechniqueStatus.TESTED_FAILED:
        recs.append("Inspect the failed simulation alert pipeline:")
        recs.append("  - Is the rule's `condition` matching the produced events?")
        recs.append("  - Are required fields (process.name, command_line, ...) present?")
        recs.append("  - Lower the threshold or shorten the time-window if too strict.")

    if tc.status is TechniqueStatus.NEEDS_DATA_SOURCE or tc.missing_logs:
        for log in tc.missing_logs:
            recs.append(f"Enable ingestion for log source: {log}.")

    if not recs:
        recs.append("Review rule coverage manually for this technique.")
    return recs


def _estimate_effort(tc: TechniqueCoverage) -> str:
    if tc.status is TechniqueStatus.NEEDS_DATA_SOURCE:
        return "High"        # Onboarding a new log source is non-trivial.
    if tc.status is TechniqueStatus.NOT_COVERED:
        return "Medium"      # New rule + scenario.
    if tc.status is TechniqueStatus.TESTED_FAILED:
        return "Medium"      # Rule debugging.
    return "Low"


class GapAnalyzer:
    """Compute and rank actionable gaps from TechniqueCoverage records."""

    def __init__(self, records: Iterable[TechniqueCoverage]) -> None:
        self._records = list(records)

    def analyse(self, only_high_risk: bool = False) -> list[Gap]:
        gaps: list[Gap] = []
        for tc in self._records:
            if not tc.status.is_gap():
                continue
            risk = _risk_for(tc)
            if only_high_risk and risk not in ("critical", "high"):
                continue
            gaps.append(Gap(
                technique_id=tc.technique_id,
                name=tc.name,
                tactic_id=tc.tactic_id,
                tactic_name=tc.tactic_name,
                status=tc.status.value,
                risk=risk,
                priority=_RISK_PRIORITY[risk],
                reasons=_build_reasons(tc),
                missing_rules=(tc.rule_count == 0),
                missing_tests=(tc.last_simulation_id is None),
                missing_scenarios=(tc.scenario_count == 0),
                missing_logs=list(tc.missing_logs),
                recommended_actions=_build_recommendations(tc),
                estimated_effort=_estimate_effort(tc),
            ))
        # Sort: highest priority first, then sub-techniques after their parents.
        gaps.sort(key=lambda g: (g.priority, g.technique_id))
        return gaps
