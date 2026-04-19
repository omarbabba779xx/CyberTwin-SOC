"""
Tests for the CyberTwin SOC AIAnalyst module.
"""

import pytest
from datetime import datetime

from backend.ai_analyst import AIAnalyst
from backend.orchestrator import SimulationOrchestrator


@pytest.fixture(scope="module")
def analysis():
    """Run a simulation and extract the AI analysis for testing."""
    orch = SimulationOrchestrator()
    orch.initialise()
    scenarios = orch.attack_engine.list_scenarios()
    sid = scenarios[0]["id"]
    result = orch.run_simulation(
        scenario_id=sid,
        duration_minutes=15,
        normal_intensity="low",
        start_time=datetime(2024, 1, 15, 9, 30),
    )
    return result["ai_analysis"]


@pytest.fixture
def analyst():
    return AIAnalyst()


class TestAIAnalyst:

    def test_analyse_incident_returns_all_sections(self, analysis):
        """The analysis should contain all expected top-level sections."""
        expected_keys = {
            "executive_narrative",
            "attack_chain_summary",
            "threat_assessment",
            "detection_gaps",
            "immediate_actions",
            "strategic_recommendations",
            "ioc_summary",
            "affected_assets_analysis",
            "compliance_impact",
            "analyst_confidence",
        }
        assert expected_keys.issubset(analysis.keys())

    def test_executive_narrative_not_empty(self, analysis):
        """The executive narrative should be a non-empty string."""
        narrative = analysis["executive_narrative"]
        assert isinstance(narrative, str)
        assert len(narrative) > 50

    def test_ioc_summary_has_categories(self, analysis):
        """The IOC summary should contain categorised indicators."""
        iocs = analysis["ioc_summary"]
        assert isinstance(iocs, dict)
        # IOC summary should have at least some content
        assert len(iocs) > 0

    def test_compliance_impact_has_frameworks(self, analysis):
        """The compliance impact section should reference security frameworks."""
        compliance = analysis["compliance_impact"]
        assert isinstance(compliance, (dict, str, list))
        # Convert to string for text search
        text = str(compliance).lower()
        # Should reference at least one common framework
        frameworks = ["nist", "iso", "gdpr", "pci", "hipaa", "soc", "mitre"]
        found = any(fw in text for fw in frameworks)
        assert found, f"No known framework found in compliance impact: {text[:200]}"

    def test_attack_chain_summary_present(self, analysis):
        """The attack chain summary should describe the attack progression."""
        chain = analysis["attack_chain_summary"]
        assert chain is not None
        assert len(str(chain)) > 0

    def test_immediate_actions_present(self, analysis):
        """Immediate actions should provide response recommendations."""
        actions = analysis["immediate_actions"]
        assert actions is not None
        assert len(str(actions)) > 0

    def test_strategic_recommendations_present(self, analysis):
        """Strategic recommendations should be present and non-empty."""
        recs = analysis["strategic_recommendations"]
        assert recs is not None
        assert len(str(recs)) > 0

    def test_classify_scenario_phishing(self, analyst):
        """A phishing scenario should be classified as 'phishing'."""
        scenario = {"id": "sc-phishing-001", "name": "Phishing Attack",
                     "description": "Spear phishing campaign", "category": "phishing"}
        result = analyst._classify_scenario(scenario)
        assert result == "phishing"

    def test_classify_scenario_brute_force(self, analyst):
        """A brute force scenario should be classified as 'brute_force'."""
        scenario = {"id": "sc-brute-001", "name": "Brute Force SSH",
                     "description": "Password guessing attack", "category": "credential_access"}
        result = analyst._classify_scenario(scenario)
        assert result == "brute_force"

    def test_analyst_confidence_present(self, analysis):
        """Analyst confidence should be present in the analysis."""
        confidence = analysis["analyst_confidence"]
        assert confidence is not None

    def test_detection_gaps_present(self, analysis):
        """Detection gaps section should be present."""
        gaps = analysis["detection_gaps"]
        assert gaps is not None
