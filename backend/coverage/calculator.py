"""
CoverageCalculator
==================
Joins the four data sources into a list of TechniqueCoverage records and a
single CoverageSummary. The calculation is *deterministic* given the same
inputs; it does not invent numbers.

Design notes
------------
- We do NOT mutate any of the source modules (rules, scenarios, cache).
- We do NOT call out over the network.
- Computing for the full 622-technique catalog must stay under ~50 ms on a
  developer laptop because we may recompute on every coverage endpoint hit.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from backend.detection.engine import DetectionEngine
from backend.detection.rules import DETECTION_RULES, DetectionRule
from backend.mitre.attack_data import MITRE_TACTICS, MITRE_TECHNIQUES

from .models import (
    HIGH_RISK_TACTICS,
    CoverageSummary,
    TechniqueCoverage,
    TechniqueStatus,
)

logger = logging.getLogger("cybertwin.coverage")


# ---------------------------------------------------------------------------
# Heuristic: required log sources per tactic / technique family
# ---------------------------------------------------------------------------

# Mapping of tactic_id -> default log sources required to detect it.
_TACTIC_LOGS: dict[str, list[str]] = {
    "TA0001": ["email", "web_access", "auth"],
    "TA0002": ["endpoint_process", "windows_event"],
    "TA0003": ["windows_event", "endpoint_process", "scheduled_task"],
    "TA0004": ["endpoint_process", "windows_event"],
    "TA0005": ["windows_event", "endpoint_process"],
    "TA0006": ["windows_event", "auth"],
    "TA0007": ["endpoint_process", "windows_event"],
    "TA0008": ["windows_event", "auth", "network_flow"],
    "TA0009": ["endpoint_process", "file_access"],
    "TA0010": ["network_flow", "proxy", "dns"],
    "TA0011": ["dns", "proxy", "network_flow"],
    "TA0040": ["endpoint_process", "file_access", "windows_event"],
    "TA0042": ["dns", "threat_intel"],
    "TA0043": ["network_flow", "dns"],
}


def _infer_required_logs(technique_id: str, tactic_id: str) -> list[str]:
    """Return a sensible default list of required logs for a technique."""
    # Specific overrides for very common techniques
    if technique_id.startswith("T1059"):    # Command & scripting interpreter
        return ["endpoint_process", "windows_event"]
    if technique_id.startswith("T1078"):    # Valid Accounts
        return ["windows_event", "auth"]
    if technique_id.startswith("T1110"):    # Brute Force
        return ["windows_event", "auth"]
    if technique_id.startswith("T1486"):    # Data Encrypted for Impact
        return ["endpoint_process", "file_access", "windows_event"]
    if technique_id.startswith("T1071"):    # Application Layer Protocol
        return ["network_flow", "proxy", "dns"]
    return _TACTIC_LOGS.get(tactic_id, ["windows_event"])


# Severity -> rule confidence multiplier (rules with higher severity have
# more weight in the global score).
_SEVERITY_WEIGHT = {
    "critical": 1.00,
    "high":     0.85,
    "medium":   0.70,
    "low":      0.55,
    "info":     0.40,
}


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------

class CoverageCalculator:
    """Compute coverage for the full MITRE ATT&CK catalog.

    Args:
        rules:       Detection rules to consider. Defaults to the built-in
                     DETECTION_RULES (plus any Sigma rules loaded by the
                     engine if `engine=` is supplied).
        scenarios:   Mapping of scenario_id -> scenario dict.
        recent_runs: Iterable of cached simulation result dicts. Each must
                     contain at minimum `scenario`, `alerts`, and a timestamp
                     under `report.generated_at` or top-level.
        available_logs: Log sources currently produced by the simulation /
                     ingestion layer. Drives the NEEDS_DATA_SOURCE status.
    """

    def __init__(
        self,
        rules: Optional[list[DetectionRule]] = None,
        scenarios: Optional[dict[str, dict]] = None,
        recent_runs: Optional[Iterable[dict]] = None,
        available_logs: Optional[list[str]] = None,
    ) -> None:
        self._rules = list(rules) if rules is not None else list(DETECTION_RULES)
        self._scenarios = scenarios or {}
        self._recent_runs = list(recent_runs or [])
        # By default, all simulated log sources are considered available.
        self._available_logs = set(available_logs or [
            "windows_event", "endpoint_process", "auth", "network_flow",
            "dns", "proxy", "email", "web_access", "file_access",
            "scheduled_task",
        ])

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def _index_rules_by_technique(self) -> dict[str, list[DetectionRule]]:
        idx: dict[str, list[DetectionRule]] = defaultdict(list)
        for r in self._rules:
            if r.technique_id:
                idx[r.technique_id].append(r)
        return idx

    def _index_scenarios_by_technique(self) -> dict[str, list[str]]:
        """Return technique_id -> [scenario_id, ...]."""
        idx: dict[str, list[str]] = defaultdict(list)
        for sid, scenario in self._scenarios.items():
            for tid in self._extract_scenario_techniques(scenario):
                idx[tid].append(sid)
        return idx

    @staticmethod
    def _extract_scenario_techniques(scenario: dict) -> set[str]:
        """Pull every technique_id mentioned by a scenario definition."""
        out: set[str] = set()
        # Common shapes: scenario["techniques"] = [...]
        for t in scenario.get("techniques", []) or []:
            if isinstance(t, str):
                out.add(t)
            elif isinstance(t, dict) and "id" in t:
                out.add(t["id"])
            elif isinstance(t, dict) and "technique_id" in t:
                out.add(t["technique_id"])
        # Or scenario["mitre"] = ["T1059.001", ...]
        for t in scenario.get("mitre", []) or []:
            if isinstance(t, str):
                out.add(t)
        # Or each step has "technique_id"
        for step in scenario.get("steps", []) or []:
            tid = step.get("technique_id")
            if tid:
                out.add(tid)
        return {tid for tid in out if tid}

    def _index_recent_detections(self) -> dict[str, dict[str, Any]]:
        """Return technique_id -> {detected, simulation_id, timestamp}.

        Looks at every cached simulation result and finds whether at least
        one alert was raised for the technique. A technique that appears in
        a scenario but never produced an alert is considered TESTED_FAILED.
        """
        out: dict[str, dict[str, Any]] = {}

        for run in self._recent_runs:
            scenario = run.get("scenario") or {}
            sid = scenario.get("id", "unknown")
            ts = (run.get("report") or {}).get("generated_at") or run.get("timestamp", "")

            # Techniques covered by this run's scenario
            covered = self._extract_scenario_techniques(scenario)

            # Techniques that produced at least one alert
            detected: set[str] = set()
            for alert in run.get("alerts", []) or []:
                tid = alert.get("technique_id")
                if tid:
                    detected.add(tid)

            for tid in covered:
                # Only update if more recent or first record
                prev = out.get(tid)
                if prev is None or (ts and ts > prev["timestamp"]):
                    out[tid] = {
                        "detected": tid in detected,
                        "simulation_id": sid,
                        "timestamp": ts,
                    }

        return out

    # ------------------------------------------------------------------
    # Core compute
    # ------------------------------------------------------------------

    def compute(self) -> tuple[list[TechniqueCoverage], CoverageSummary]:
        rules_by_tid = self._index_rules_by_technique()
        scenarios_by_tid = self._index_scenarios_by_technique()
        recent_by_tid = self._index_recent_detections()

        records: list[TechniqueCoverage] = []

        for tid, info in MITRE_TECHNIQUES.items():
            tactic_id = info.get("tactic", "")
            tactic_name = (MITRE_TACTICS.get(tactic_id) or {}).get("name", "Unknown")
            is_sub = bool(info.get("is_subtechnique") or "." in tid)

            rules = rules_by_tid.get(tid, [])
            scenarios = scenarios_by_tid.get(tid, [])
            recent = recent_by_tid.get(tid)

            required_logs = _infer_required_logs(tid, tactic_id)
            # Aggregate explicit required_logs from rules (more authoritative)
            for r in rules:
                if r.required_logs:
                    required_logs = sorted(set(required_logs) | set(r.required_logs))
                    break
            missing_logs = [l for l in required_logs if l not in self._available_logs]
            available_logs = [l for l in required_logs if l in self._available_logs]

            # Confidence: weighted average of rule confidences * severity weight
            conf = 0.0
            if rules:
                conf = sum(
                    r.confidence * _SEVERITY_WEIGHT.get(r.severity, 0.5)
                    for r in rules
                ) / len(rules)

            status = self._classify(
                rules=rules,
                scenarios=scenarios,
                recent=recent,
                missing_logs=missing_logs,
            )

            records.append(TechniqueCoverage(
                technique_id=tid,
                name=info.get("name", tid),
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                is_subtechnique=is_sub,
                rules=[r.rule_id for r in rules],
                rule_count=len(rules),
                scenarios=list(scenarios),
                scenario_count=len(scenarios),
                last_simulation_id=(recent or {}).get("simulation_id"),
                last_simulation_at=(recent or {}).get("timestamp"),
                last_simulation_detected=(recent or {}).get("detected"),
                confidence=round(conf, 2),
                required_logs=required_logs,
                available_logs=available_logs,
                missing_logs=missing_logs,
                status=status,
            ))

        summary = self._summarise(records)
        return records, summary

    # ------------------------------------------------------------------
    # Classification logic
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(
        *,
        rules: list[DetectionRule],
        scenarios: list[str],
        recent: Optional[dict[str, Any]],
        missing_logs: list[str],
    ) -> TechniqueStatus:
        # No rule mapped at all.
        if not rules:
            return TechniqueStatus.NOT_COVERED

        # Rule exists but the data sources to evaluate it are missing.
        if missing_logs and len(missing_logs) == len(set(missing_logs)) > 0 \
           and len(missing_logs) >= 1 and not recent:
            # Soft trigger: only when no recent run AND at least one log missing.
            # Avoids false positives once a run has been performed.
            if len(missing_logs) >= len(rules[0].required_logs or []) > 0:
                return TechniqueStatus.NEEDS_DATA_SOURCE

        # We have a rule + we have evidence of a run that covered the technique.
        if recent is not None:
            if recent.get("detected"):
                return TechniqueStatus.TESTED_DETECTED
            return TechniqueStatus.TESTED_FAILED

        # Rule exists, scenarios cover the technique, but never simulated.
        if scenarios:
            return TechniqueStatus.RULE_UNTESTED

        # Rule exists in catalog only — never wired to a scenario.
        return TechniqueStatus.RULE_EXISTS

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise(records: list[TechniqueCoverage]) -> CoverageSummary:
        s = CoverageSummary()
        s.catalog_total = len(records)
        s.last_recalculated_at = datetime.now(timezone.utc).isoformat()

        by_status: dict[str, int] = defaultdict(int)
        for r in records:
            by_status[r.status.value] += 1
        s.by_status = dict(by_status)

        s.validated = by_status.get(TechniqueStatus.TESTED_DETECTED.value, 0)
        s.failed    = by_status.get(TechniqueStatus.TESTED_FAILED.value, 0)
        s.untested  = by_status.get(TechniqueStatus.RULE_UNTESTED.value, 0) \
                    + by_status.get(TechniqueStatus.RULE_EXISTS.value, 0)
        s.not_covered = by_status.get(TechniqueStatus.NOT_COVERED.value, 0)

        s.tested = s.validated + s.failed
        s.rule_mapped = s.validated + s.failed + s.untested

        s.high_risk_gaps = sum(
            1 for r in records
            if r.status.is_gap() and r.tactic_id in HIGH_RISK_TACTICS
        )

        # Global Score (0..100):
        #   - 3 points per validated technique (the gold standard).
        #   - 1 point per rule-mapped technique (rule exists, even if untested).
        # Theoretical max per technique = 3, so max_score = catalog * 3.
        # The high_risk_gaps count is exposed as its own metric, NOT subtracted
        # from the score (subtraction was making catalogs with thousands of
        # legitimate gaps score 0 even with several validated detections).
        if s.catalog_total:
            raw = s.validated * 3.0 + (s.untested + s.failed) * 1.0
            max_score = s.catalog_total * 3.0
            s.global_score = round(max(0.0, min(100.0, raw / max_score * 100)), 1)
        else:
            s.global_score = 0.0

        return s


def build_default_calculator() -> CoverageCalculator:
    """Construct a calculator from the live engine + cached simulation runs.

    Falls back to an empty calculator if the orchestrator is not yet bound,
    which is the case during unit tests.
    """
    rules = list(DETECTION_RULES)
    scenarios: dict[str, dict] = {}
    recent_runs: list[dict] = []

    try:
        # Try to pull the singleton engine + its sigma rules
        engine = DetectionEngine()
        rules = list(engine._rules)  # noqa: SLF001 - engine exposes no public accessor yet
    except Exception as exc:
        logger.warning("Could not load DetectionEngine rules: %s", exc)

    # Scenarios - lazy import to avoid circular reference
    try:
        from backend.simulation.attack_engine import AttackScenarioEngine
        ae = AttackScenarioEngine()
        ae.load_scenarios()
        scenarios = dict(ae._scenarios)  # noqa: SLF001
    except Exception as exc:
        logger.warning("Could not load AttackScenarioEngine scenarios: %s", exc)

    # Recent simulation results - from cache if any
    try:
        from backend.cache import cache
        # Cache exposes either get_all_keys() (memory) or scan_iter (Redis).
        keys = []
        if hasattr(cache, "scan_iter"):
            keys = list(cache.scan_iter("result:*"))
        elif hasattr(cache, "_store"):
            keys = [k for k in cache._store if k.startswith("result:")]  # noqa: SLF001
        for k in keys:
            run = cache.get(k)
            if isinstance(run, dict):
                recent_runs.append(run)
    except Exception as exc:
        logger.debug("No cached runs available for coverage: %s", exc)

    return CoverageCalculator(
        rules=rules,
        scenarios=scenarios,
        recent_runs=recent_runs,
    )
