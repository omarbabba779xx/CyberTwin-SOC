"""Tests for backend.coverage — Detection Coverage Center (Phase 2)."""

from __future__ import annotations

import pytest

from backend.coverage import (
    CoverageCalculator,
    GapAnalyzer,
    TechniqueStatus,
)
from backend.coverage.models import HIGH_RISK_TACTICS
from backend.detection.rules import DETECTION_RULES, DetectionRule


def _empty_condition(events):
    return []


# ---------------------------------------------------------------------------
# CoverageCalculator
# ---------------------------------------------------------------------------

class TestCoverageCalculator:

    def test_runs_against_full_catalog(self):
        """Calculator must produce one record per technique in the catalog."""
        from backend.mitre.attack_data import MITRE_TECHNIQUES
        calc = CoverageCalculator(rules=[], scenarios={}, recent_runs=[])
        records, summary = calc.compute()
        assert len(records) == len(MITRE_TECHNIQUES)
        assert summary.catalog_total == len(records)

    def test_no_rules_means_not_covered(self):
        calc = CoverageCalculator(rules=[], scenarios={}, recent_runs=[])
        records, summary = calc.compute()
        # With zero rules, every technique should be NOT_COVERED.
        assert all(r.status is TechniqueStatus.NOT_COVERED for r in records)
        assert summary.not_covered == summary.catalog_total
        assert summary.validated == 0
        assert summary.global_score == 0.0

    def test_rule_only_gives_rule_exists(self):
        rule = DetectionRule(
            rule_id="RULE-TEST", name="t", description="t", severity="high",
            tactic="Execution", technique_id="T1059.001",
            technique_name="PowerShell", condition=_empty_condition,
        )
        calc = CoverageCalculator(rules=[rule], scenarios={}, recent_runs=[])
        records, _ = calc.compute()
        target = next(r for r in records if r.technique_id == "T1059.001")
        assert target.status is TechniqueStatus.RULE_EXISTS
        assert target.rule_count == 1
        assert "RULE-TEST" in target.rules

    def test_rule_plus_scenario_gives_untested(self):
        rule = DetectionRule(
            rule_id="RULE-TEST", name="t", description="t", severity="high",
            tactic="Execution", technique_id="T1059.001",
            technique_name="PowerShell", condition=_empty_condition,
        )
        scenarios = {"sc-1": {"id": "sc-1", "techniques": ["T1059.001"]}}
        calc = CoverageCalculator(rules=[rule], scenarios=scenarios, recent_runs=[])
        records, _ = calc.compute()
        target = next(r for r in records if r.technique_id == "T1059.001")
        assert target.status is TechniqueStatus.RULE_UNTESTED
        assert "sc-1" in target.scenarios

    def test_simulation_with_alert_validates_technique(self):
        rule = DetectionRule(
            rule_id="RULE-TEST", name="t", description="t", severity="high",
            tactic="Execution", technique_id="T1059.001",
            technique_name="PowerShell", condition=_empty_condition,
        )
        scenarios = {"sc-1": {"id": "sc-1", "techniques": ["T1059.001"]}}
        run = {
            "scenario": {"id": "sc-1", "techniques": ["T1059.001"]},
            "alerts": [{"technique_id": "T1059.001"}],
            "report": {"generated_at": "2026-04-26T10:00:00Z"},
        }
        calc = CoverageCalculator(rules=[rule], scenarios=scenarios, recent_runs=[run])
        records, summary = calc.compute()
        target = next(r for r in records if r.technique_id == "T1059.001")
        assert target.status is TechniqueStatus.TESTED_DETECTED
        assert target.last_simulation_detected is True
        assert summary.validated == 1
        assert summary.global_score > 0

    def test_simulation_without_alert_marks_failed(self):
        rule = DetectionRule(
            rule_id="RULE-TEST", name="t", description="t", severity="high",
            tactic="Execution", technique_id="T1059.001",
            technique_name="PowerShell", condition=_empty_condition,
        )
        scenarios = {"sc-1": {"id": "sc-1", "techniques": ["T1059.001"]}}
        run = {
            "scenario": {"id": "sc-1", "techniques": ["T1059.001"]},
            "alerts": [],
            "report": {"generated_at": "2026-04-26T10:00:00Z"},
        }
        calc = CoverageCalculator(rules=[rule], scenarios=scenarios, recent_runs=[run])
        records, summary = calc.compute()
        target = next(r for r in records if r.technique_id == "T1059.001")
        assert target.status is TechniqueStatus.TESTED_FAILED
        assert summary.failed == 1

    def test_global_score_is_bounded(self):
        """Global score must stay in [0, 100] regardless of inputs."""
        # Mass-validate every technique to push score to its max.
        from backend.mitre.attack_data import MITRE_TECHNIQUES
        rules = []
        scenarios = {}
        runs = []
        for i, tid in enumerate(list(MITRE_TECHNIQUES.keys())[:50]):
            rules.append(DetectionRule(
                rule_id=f"R{i:03d}", name="r", description="r", severity="critical",
                tactic="Execution", technique_id=tid, technique_name=tid,
                condition=_empty_condition,
            ))
            sid = f"sc-{i}"
            scenarios[sid] = {"id": sid, "techniques": [tid]}
            runs.append({
                "scenario": {"id": sid, "techniques": [tid]},
                "alerts": [{"technique_id": tid}],
                "report": {"generated_at": "2026-04-26T10:00:00Z"},
            })
        calc = CoverageCalculator(rules=rules, scenarios=scenarios, recent_runs=runs)
        _, summary = calc.compute()
        assert 0.0 <= summary.global_score <= 100.0
        assert summary.validated == 50

    def test_with_real_built_in_rules(self):
        """Smoke test: the live DETECTION_RULES list integrates without error."""
        calc = CoverageCalculator(
            rules=list(DETECTION_RULES), scenarios={}, recent_runs=[],
        )
        records, summary = calc.compute()
        assert summary.catalog_total > 0
        # At least some techniques must be rule-mapped (we ship 46 rules).
        assert summary.rule_mapped >= 1
        assert sum(summary.by_status.values()) == summary.catalog_total


# ---------------------------------------------------------------------------
# GapAnalyzer
# ---------------------------------------------------------------------------

class TestGapAnalyzer:

    def test_no_records_no_gaps(self):
        gaps = GapAnalyzer([]).analyse()
        assert gaps == []

    def test_validated_technique_is_not_a_gap(self):
        rule = DetectionRule(
            rule_id="RULE-TEST", name="t", description="t", severity="high",
            tactic="Execution", technique_id="T1059.001",
            technique_name="PowerShell", condition=_empty_condition,
        )
        scenarios = {"sc-1": {"id": "sc-1", "techniques": ["T1059.001"]}}
        run = {
            "scenario": {"id": "sc-1", "techniques": ["T1059.001"]},
            "alerts": [{"technique_id": "T1059.001"}],
        }
        calc = CoverageCalculator(rules=[rule], scenarios=scenarios, recent_runs=[run])
        records, _ = calc.compute()
        gaps = GapAnalyzer(records).analyse()
        assert all(g.technique_id != "T1059.001" for g in gaps)

    def test_high_risk_filter(self):
        calc = CoverageCalculator(rules=[], scenarios={}, recent_runs=[])
        records, _ = calc.compute()
        all_gaps = GapAnalyzer(records).analyse()
        hr_gaps = GapAnalyzer(records).analyse(only_high_risk=True)
        assert len(hr_gaps) <= len(all_gaps)
        # The filter must guarantee the risk level, but any tactic can produce
        # a high-risk gap (NOT_COVERED already maps to 'high' regardless of
        # tactic; HIGH_RISK_TACTICS just upgrades it further to 'critical').
        assert all(g.risk in ("critical", "high") for g in hr_gaps)
        # 'critical' gaps must come from a high-risk tactic.
        assert all(
            g.tactic_id in HIGH_RISK_TACTICS
            for g in hr_gaps if g.risk == "critical"
        )

    def test_gaps_are_sorted_by_priority(self):
        calc = CoverageCalculator(rules=[], scenarios={}, recent_runs=[])
        records, _ = calc.compute()
        gaps = GapAnalyzer(records).analyse()
        priorities = [g.priority for g in gaps]
        assert priorities == sorted(priorities)

    def test_gap_carries_actionable_recommendations(self):
        calc = CoverageCalculator(rules=[], scenarios={}, recent_runs=[])
        records, _ = calc.compute()
        gaps = GapAnalyzer(records).analyse()
        sample = gaps[0]
        assert sample.recommended_actions, "Every gap must have at least one recommendation"
        assert sample.reasons, "Every gap must explain why"
        assert sample.estimated_effort in ("Low", "Medium", "High")


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------

class TestCoverageEndpoints:

    def test_summary_requires_auth(self, client):
        r = client.get("/api/coverage/summary")
        assert r.status_code == 401

    def test_summary_returns_full_shape(self, client, auth_headers):
        r = client.get("/api/coverage/summary", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        # All summary fields must be present
        for key in ("catalog_total", "by_status", "rule_mapped", "tested",
                    "validated", "failed", "untested", "not_covered",
                    "high_risk_gaps", "global_score", "last_recalculated_at"):
            assert key in body, f"Missing key {key} in summary response"
        assert body["catalog_total"] >= 600     # full enterprise catalog
        assert 0.0 <= body["global_score"] <= 100.0

    def test_mitre_table_returns_records(self, client, auth_headers):
        r = client.get("/api/coverage/mitre", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert "records" in body and "total" in body
        assert body["total"] == len(body["records"])
        assert body["total"] >= 600

    def test_mitre_table_filters(self, client, auth_headers):
        r = client.get("/api/coverage/mitre?status=not_covered", headers=auth_headers)
        assert r.status_code == 200
        for rec in r.json()["records"]:
            assert rec["status"] == "not_covered"

    def test_technique_detail_known(self, client, auth_headers):
        r = client.get("/api/coverage/technique/T1059.001", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["technique_id"] == "T1059.001"
        assert "status" in body

    def test_technique_detail_unknown_404(self, client, auth_headers):
        r = client.get("/api/coverage/technique/T9999.999", headers=auth_headers)
        assert r.status_code == 404

    def test_gaps_endpoint(self, client, auth_headers):
        r = client.get("/api/coverage/gaps?limit=10", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body["gaps"], list)
        # Every gap must carry the operational fields
        for g in body["gaps"]:
            assert "technique_id" in g and "risk" in g and "priority" in g
            assert g["risk"] in ("critical", "high", "medium", "low")

    def test_high_risk_endpoint(self, client, auth_headers):
        r = client.get("/api/coverage/gaps/high-risk?limit=5", headers=auth_headers)
        assert r.status_code == 200
        for g in r.json()["gaps"]:
            assert g["risk"] in ("critical", "high")

    def test_recalculate_requires_admin(self, client, auth_headers, admin_headers):
        # analyst role cannot configure_system
        r1 = client.post("/api/coverage/recalculate", headers=auth_headers)
        assert r1.status_code == 403
        # admin can
        r2 = client.post("/api/coverage/recalculate", headers=admin_headers)
        assert r2.status_code == 200
        body = r2.json()
        assert body["status"] == "recalculated"
        assert "summary" in body
