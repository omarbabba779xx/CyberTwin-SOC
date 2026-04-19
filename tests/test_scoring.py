"""
Tests for the CyberTwin SOC ScoringEngine.
"""

import pytest
from backend.scoring import ScoringEngine


@pytest.fixture
def engine():
    return ScoringEngine()


@pytest.fixture
def sample_scenario():
    return {
        "phases": [
            {"technique_id": "T1110", "name": "Brute Force"},
            {"technique_id": "T1046", "name": "Port Scan"},
            {"technique_id": "T1548", "name": "Privilege Escalation"},
        ],
        "mitre_techniques_summary": ["T1110", "T1046", "T1548"],
    }


@pytest.fixture
def sample_alerts():
    return [
        {
            "technique_id": "T1110",
            "timestamp": "2024-01-01T10:00:30",
            "severity": "high",
            "affected_hosts": ["srv-web-01"],
            "affected_users": ["admin"],
        },
        {
            "technique_id": "T1046",
            "timestamp": "2024-01-01T10:05:00",
            "severity": "high",
            "affected_hosts": ["srv-web-01"],
            "affected_users": [],
        },
    ]


@pytest.fixture
def sample_logs():
    return [
        {"log_source": "authentication", "technique_id": "T1110", "timestamp": "2024-01-01T10:00:00"},
        {"log_source": "process", "technique_id": "T1046", "timestamp": "2024-01-01T10:04:30"},
        {"log_source": "network", "timestamp": "2024-01-01T10:01:00"},
        {"log_source": "firewall", "timestamp": "2024-01-01T10:02:00"},
        {"log_source": "dns", "timestamp": "2024-01-01T10:03:00"},
        {"log_source": "file_access", "timestamp": "2024-01-01T10:06:00"},
    ]


class TestScoringEngine:

    def test_calculate_scores_returns_all_keys(self, engine, sample_scenario, sample_alerts, sample_logs):
        """Verify that calculate_scores returns all expected top-level keys."""
        result = engine.calculate_scores(sample_scenario, sample_alerts, sample_logs)
        expected_keys = {
            "detection_score", "coverage_score", "response_score",
            "visibility_score", "overall_score", "risk_level",
            "maturity_level", "details", "recommendations",
        }
        assert expected_keys.issubset(result.keys())

    def test_detection_score_with_alerts(self, engine, sample_scenario, sample_alerts, sample_logs):
        """With 2 out of 3 phases detected, detection_score should be ~66.7."""
        result = engine.calculate_scores(sample_scenario, sample_alerts, sample_logs)
        assert result["detection_score"] == pytest.approx(66.7, abs=0.1)

    def test_detection_score_no_alerts(self, engine, sample_scenario, sample_logs):
        """With zero alerts, detection_score should be 0."""
        result = engine.calculate_scores(sample_scenario, [], sample_logs)
        assert result["detection_score"] == 0.0

    def test_coverage_score_with_matching_techniques(self, engine, sample_scenario, sample_alerts, sample_logs):
        """2 out of 3 expected techniques detected should yield ~66.7."""
        result = engine.calculate_scores(sample_scenario, sample_alerts, sample_logs)
        assert result["coverage_score"] == pytest.approx(66.7, abs=0.1)

    def test_coverage_score_parent_child_matching(self, engine):
        """T1110 in phases should match T1110.001 in alerts (parent-child)."""
        scenario = {
            "phases": [{"technique_id": "T1110"}],
            "mitre_techniques_summary": ["T1110"],
        }
        alerts = [{"technique_id": "T1110.001", "timestamp": "2024-01-01T10:00:30"}]
        logs = [{"log_source": "authentication", "technique_id": "T1110", "timestamp": "2024-01-01T10:00:00"}]
        result = engine.calculate_scores(scenario, alerts, logs)
        assert result["coverage_score"] == 100.0

    def test_visibility_score_all_sources(self, engine):
        """When all 12 expected log sources are present, visibility should be 100."""
        all_sources = [
            "authentication", "process", "file_access", "network",
            "firewall", "dns", "web_access", "email", "application",
            "database", "security", "ids",
        ]
        logs = [{"log_source": s} for s in all_sources]
        scenario = {"phases": [], "mitre_techniques_summary": []}
        result = engine.calculate_scores(scenario, [], logs)
        assert result["visibility_score"] == 100.0

    def test_visibility_score_partial(self, engine):
        """With only 3 of 12 sources, visibility should be 25."""
        logs = [
            {"log_source": "authentication"},
            {"log_source": "network"},
            {"log_source": "firewall"},
        ]
        scenario = {"phases": [], "mitre_techniques_summary": []}
        result = engine.calculate_scores(scenario, [], logs)
        assert result["visibility_score"] == 25.0

    def test_response_score_fast_detection(self, engine):
        """With TTD <= 60 seconds, response_score should be 100."""
        scenario = {
            "phases": [{"technique_id": "T1110"}],
            "mitre_techniques_summary": ["T1110"],
        }
        logs = [{"log_source": "authentication", "technique_id": "T1110", "timestamp": "2024-01-01T10:00:00"}]
        alerts = [{"technique_id": "T1110", "timestamp": "2024-01-01T10:00:30"}]
        result = engine.calculate_scores(scenario, alerts, logs)
        assert result["response_score"] == 100.0

    def test_overall_score_weighted_correctly(self, engine, sample_scenario, sample_alerts, sample_logs):
        """Overall score should equal the weighted sum of sub-scores."""
        result = engine.calculate_scores(sample_scenario, sample_alerts, sample_logs)
        expected = round(
            result["detection_score"] * 0.35
            + result["coverage_score"] * 0.30
            + result["response_score"] * 0.15
            + result["visibility_score"] * 0.20,
            1,
        )
        assert result["overall_score"] == pytest.approx(expected, abs=0.2)

    def test_risk_level_critical(self, engine):
        """overall < 40 should be Critical risk."""
        assert engine._risk_level(20) == "Critical"

    def test_risk_level_high(self, engine):
        """40 <= overall < 60 should be High risk."""
        assert engine._risk_level(50) == "High"

    def test_risk_level_medium(self, engine):
        """60 <= overall < 80 should be Medium risk."""
        assert engine._risk_level(65) == "Medium"

    def test_risk_level_low(self, engine):
        """overall >= 80 should be Low risk."""
        assert engine._risk_level(90) == "Low"

    def test_maturity_level_initial(self, engine):
        """overall < 30 should be Initial maturity."""
        assert engine._maturity_level(10) == "Initial"

    def test_maturity_level_optimized(self, engine):
        """overall >= 85 should be Optimized maturity."""
        assert engine._maturity_level(90) == "Optimized"

    def test_technique_matches_exact(self):
        """Exact technique match should return True."""
        assert ScoringEngine._technique_matches("T1110", "T1110") is True

    def test_technique_matches_parent_child(self):
        """Parent T1110 should match child T1110.001."""
        assert ScoringEngine._technique_matches("T1110", "T1110.001") is True

    def test_technique_matches_empty(self):
        """Empty technique IDs should return False."""
        assert ScoringEngine._technique_matches("", "T1110") is False
