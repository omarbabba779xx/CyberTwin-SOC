"""Data models for the Detection Coverage Center."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class TechniqueStatus(str, Enum):
    """Honest, mutually exclusive coverage status for one MITRE technique.

    The order below is also the priority for upgrading a status as more
    evidence becomes available (lowest = worst, highest = best).
    """

    NOT_COVERED          = "not_covered"
    NEEDS_DATA_SOURCE    = "needs_data_source"
    RULE_EXISTS          = "rule_exists"
    RULE_UNTESTED        = "rule_exists_untested"
    TESTED_FAILED        = "tested_but_failed"
    NOISY                = "noisy"
    TESTED_DETECTED      = "tested_and_detected"
    NOT_APPLICABLE       = "not_applicable"

    def is_validated(self) -> bool:
        return self is TechniqueStatus.TESTED_DETECTED

    def is_gap(self) -> bool:
        """True when this status counts as a coverage gap to address."""
        return self in {
            TechniqueStatus.NOT_COVERED,
            TechniqueStatus.NEEDS_DATA_SOURCE,
            TechniqueStatus.RULE_UNTESTED,
            TechniqueStatus.TESTED_FAILED,
        }


# Tactics that warrant elevated risk weighting in gap prioritisation.
HIGH_RISK_TACTICS = {
    "TA0001",   # Initial Access
    "TA0002",   # Execution
    "TA0004",   # Privilege Escalation
    "TA0005",   # Defense Evasion
    "TA0006",   # Credential Access
    "TA0008",   # Lateral Movement
    "TA0010",   # Exfiltration
    "TA0040",   # Impact
}


@dataclass
class TechniqueCoverage:
    """Computed coverage record for a single MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic_id: str
    tactic_name: str
    is_subtechnique: bool

    # Rules referencing this technique
    rules: list[str] = field(default_factory=list)
    rule_count: int = 0

    # Scenarios that exercise this technique
    scenarios: list[str] = field(default_factory=list)
    scenario_count: int = 0

    # Last simulation evidence
    last_simulation_id: Optional[str] = None
    last_simulation_at: Optional[str] = None
    last_simulation_detected: Optional[bool] = None

    # Aggregated metadata
    confidence: float = 0.0
    required_logs: list[str] = field(default_factory=list)
    available_logs: list[str] = field(default_factory=list)
    missing_logs: list[str] = field(default_factory=list)

    # Final status
    status: TechniqueStatus = TechniqueStatus.NOT_COVERED

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class CoverageSummary:
    """Aggregate coverage figures for the whole catalog."""

    catalog_total: int = 0
    by_status: dict[str, int] = field(default_factory=dict)

    rule_mapped: int = 0
    tested: int = 0
    validated: int = 0
    failed: int = 0
    untested: int = 0
    not_covered: int = 0
    high_risk_gaps: int = 0

    # Score in 0..100 — favours validated coverage, penalises gaps.
    global_score: float = 0.0

    last_recalculated_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Gap:
    """A single, actionable detection coverage gap."""

    technique_id: str
    name: str
    tactic_id: str
    tactic_name: str
    status: str
    risk: str                          # "low" | "medium" | "high" | "critical"
    priority: int                      # 1 = highest
    reasons: list[str] = field(default_factory=list)
    missing_rules: bool = False
    missing_tests: bool = False
    missing_scenarios: bool = False
    missing_logs: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    estimated_effort: str = "Medium"   # "Low" | "Medium" | "High"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
