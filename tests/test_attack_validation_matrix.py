"""Validated ATT&CK coverage smoke matrix.

These tests execute representative built-in scenarios and assert that the
simulation + telemetry + detection chain emits concrete ATT&CK technique hits.
They are intentionally not full ATT&CK certification; they are regression
guards for CyberTwin's own validated paths.
"""

from __future__ import annotations

import pytest

from backend.orchestrator import SimulationOrchestrator


@pytest.fixture(scope="module")
def orchestrator():
    orch = SimulationOrchestrator()
    orch.initialise()
    return orch


@pytest.mark.parametrize(
    ("scenario_id", "expected_any"),
    [
        ("sc-bruteforce-001", {"T1046", "T1068", "T1110", "T1496"}),
        ("sc-phishing-001", {"T1005", "T1041", "T1059.003", "T1087.002", "T1566"}),
    ],
)
def test_representative_scenarios_validate_attack_techniques(orchestrator, scenario_id, expected_any):
    result = orchestrator.run_simulation(
        scenario_id,
        duration_minutes=5,
        normal_intensity="low",
    )
    detected = {a.get("technique_id") for a in result["alerts"] if a.get("technique_id")}

    assert len(result["logs"]) > 0
    assert len(result["alerts"]) > 0
    assert detected & expected_any
    assert result["scores"]["coverage_score"] > 0
