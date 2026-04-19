"""
Tests for the CyberTwin SOC AttackScenarioEngine.
"""

import pytest
from datetime import datetime

from backend.simulation.attack_engine import AttackScenarioEngine


@pytest.fixture
def engine():
    eng = AttackScenarioEngine(seed=42)
    eng.load_scenarios()
    return eng


class TestAttackScenarioEngine:

    def test_load_scenarios_from_json(self, engine):
        """load_scenarios should load at least one scenario."""
        assert len(engine._scenarios) > 0

    def test_list_scenarios_returns_4(self, engine):
        """There should be 4 scenario files (brute_force, exfiltration, lateral_movement, phishing)."""
        scenarios = engine.list_scenarios()
        assert len(scenarios) == 4

    def test_scenario_has_required_fields(self, engine):
        """Each scenario summary should have id, name, description, and phases count."""
        scenarios = engine.list_scenarios()
        for s in scenarios:
            assert "id" in s
            assert "name" in s
            assert "description" in s
            assert "phases" in s
            assert isinstance(s["phases"], int)

    def test_run_scenario_generates_events(self, engine):
        """Generating attack events for a known scenario should produce events."""
        scenarios = engine.list_scenarios()
        sid = scenarios[0]["id"]
        events = engine.generate_attack_events(sid, start_time=datetime(2024, 1, 1, 10, 0))
        assert len(events) > 0

    def test_brute_force_generates_enough_events(self, engine):
        """The brute force scenario should produce at least 25 events (many failed logins)."""
        # Find brute force scenario
        scenarios = engine.list_scenarios()
        bf_id = None
        for s in scenarios:
            if "brute" in s["name"].lower() or "brute" in s["id"].lower():
                bf_id = s["id"]
                break
        assert bf_id is not None, "Brute force scenario not found"
        events = engine.generate_attack_events(bf_id, start_time=datetime(2024, 1, 1, 10, 0))
        assert len(events) >= 25

    def test_scenario_events_have_required_fields(self, engine):
        """Each generated event should have timestamp, event_id, and is_malicious."""
        scenarios = engine.list_scenarios()
        sid = scenarios[0]["id"]
        events = engine.generate_attack_events(sid, start_time=datetime(2024, 1, 1, 10, 0))
        for e in events:
            assert "timestamp" in e
            assert "event_id" in e
            assert e["is_malicious"] is True

    def test_unknown_scenario_raises_error(self, engine):
        """Requesting an unknown scenario should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown scenario"):
            engine.generate_attack_events("sc-nonexistent-999")

    def test_get_scenario_returns_dict(self, engine):
        """get_scenario should return the full scenario dict for a valid ID."""
        scenarios = engine.list_scenarios()
        sid = scenarios[0]["id"]
        scenario = engine.get_scenario(sid)
        assert isinstance(scenario, dict)
        assert "phases" in scenario

    def test_get_scenario_unknown_returns_none(self, engine):
        """get_scenario for unknown ID should return None."""
        assert engine.get_scenario("nonexistent") is None

    def test_events_sorted_by_timestamp(self, engine):
        """Generated events should be sorted chronologically."""
        scenarios = engine.list_scenarios()
        sid = scenarios[0]["id"]
        events = engine.generate_attack_events(sid, start_time=datetime(2024, 1, 1, 10, 0))
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps)
