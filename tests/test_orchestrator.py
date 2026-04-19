"""
Tests for the CyberTwin SOC SimulationOrchestrator.
"""

import pytest
from datetime import datetime

from backend.orchestrator import SimulationOrchestrator


@pytest.fixture(scope="module")
def orchestrator_result():
    """Run one simulation and share the result across all tests in this module."""
    orch = SimulationOrchestrator()
    orch.initialise()
    scenarios = orch.attack_engine.list_scenarios()
    sid = scenarios[0]["id"]
    result = orch.run_simulation(
        scenario_id=sid,
        duration_minutes=30,
        normal_intensity="low",
        start_time=datetime(2024, 1, 15, 9, 30),
    )
    return result


class TestSimulationOrchestrator:

    def test_initialise_loads_environment(self):
        """After initialise, the environment should contain hosts and users."""
        orch = SimulationOrchestrator()
        orch.initialise()
        assert len(orch.environment.get_hosts()) > 0
        assert len(orch.environment.get_users()) > 0
        assert len(orch.attack_engine.list_scenarios()) > 0

    def test_run_simulation_returns_complete_result(self, orchestrator_result):
        """The simulation result should be a dict (not None)."""
        assert orchestrator_result is not None
        assert isinstance(orchestrator_result, dict)

    def test_result_contains_logs_alerts_scores(self, orchestrator_result):
        """The result should contain logs, alerts, and scores."""
        assert "logs" in orchestrator_result
        assert "alerts" in orchestrator_result
        assert "scores" in orchestrator_result
        assert len(orchestrator_result["logs"]) > 0

    def test_result_contains_ai_analysis(self, orchestrator_result):
        """The result should contain an ai_analysis section."""
        assert "ai_analysis" in orchestrator_result
        ai = orchestrator_result["ai_analysis"]
        assert isinstance(ai, dict)
        assert "executive_narrative" in ai

    def test_result_contains_report(self, orchestrator_result):
        """The result should contain a report section."""
        assert "report" in orchestrator_result
        assert isinstance(orchestrator_result["report"], dict)

    def test_result_contains_incidents(self, orchestrator_result):
        """The result should contain incidents."""
        assert "incidents" in orchestrator_result
        assert isinstance(orchestrator_result["incidents"], list)

    def test_result_contains_mitre_coverage(self, orchestrator_result):
        """The result should contain MITRE coverage data."""
        assert "mitre_coverage" in orchestrator_result
        mc = orchestrator_result["mitre_coverage"]
        assert "coverage_matrix" in mc

    def test_result_has_event_counts(self, orchestrator_result):
        """The result should have normal, attack, and total event counts."""
        assert "normal_events_count" in orchestrator_result
        assert "attack_events_count" in orchestrator_result
        assert "total_events" in orchestrator_result
        assert orchestrator_result["total_events"] > 0

    def test_scores_have_all_dimensions(self, orchestrator_result):
        """Scores should include all four dimensions plus overall."""
        scores = orchestrator_result["scores"]
        assert "detection_score" in scores
        assert "coverage_score" in scores
        assert "response_score" in scores
        assert "visibility_score" in scores
        assert "overall_score" in scores
        assert "risk_level" in scores

    def test_result_contains_timeline(self, orchestrator_result):
        """The result should contain a timeline."""
        assert "timeline" in orchestrator_result
        assert len(orchestrator_result["timeline"]) > 0

    def test_get_last_result(self):
        """get_last_result should return the most recent simulation result."""
        orch = SimulationOrchestrator()
        orch.initialise()
        scenarios = orch.attack_engine.list_scenarios()
        sid = scenarios[0]["id"]
        orch.run_simulation(sid, duration_minutes=15, normal_intensity="low",
                            start_time=datetime(2024, 1, 15, 9, 30))
        last = orch.get_last_result()
        assert last is not None
        assert "scores" in last
