"""
Quick start script for CyberTwin SOC.

Usage:
    python run.py              # Start the FastAPI backend on port 8000
    python run.py --demo       # Run a demo simulation and print the report
"""

import argparse
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))


def start_server():
    """Start the FastAPI server."""
    import uvicorn
    print("\n  CyberTwin SOC — Starting API server...")
    print("  Dashboard API: http://localhost:8000")
    print("  API Docs:      http://localhost:8000/docs\n")
    uvicorn.run("backend.api.main:app", host="0.0.0.0", port=8000, reload=True)


def run_demo():
    """Run a quick demo simulation and print results."""
    from backend.orchestrator import SimulationOrchestrator

    print("\n" + "=" * 60)
    print("  CyberTwin SOC — Demo Simulation")
    print("=" * 60)

    orch = SimulationOrchestrator()
    orch.initialise()

    scenarios = orch.attack_engine.list_scenarios()
    print(f"\n  Available scenarios ({len(scenarios)}):")
    for s in scenarios:
        print(f"    - {s['id']}: {s['name']} [{s['severity']}]")

    # Run first scenario
    scenario_id = scenarios[0]["id"]
    print(f"\n  Running scenario: {scenario_id}...")
    result = orch.run_simulation(scenario_id, duration_minutes=30)

    scores = result["scores"]
    print(f"\n  Results:")
    print(f"    Total Events:     {result['total_events']}")
    print(f"    Total Logs:       {result['total_logs']}")
    print(f"    Alerts:           {len(result['alerts'])}")
    print(f"    Incidents:        {len(result['incidents'])}")
    print(f"\n  Scores:")
    print(f"    Detection:        {scores['detection_score']}/100")
    print(f"    MITRE Coverage:   {scores['coverage_score']}/100")
    print(f"    Response:         {scores['response_score']}/100")
    print(f"    Visibility:       {scores['visibility_score']}/100")
    print(f"    Overall:          {scores['overall_score']}/100")
    print(f"    Risk Level:       {scores['risk_level']}")
    print(f"    Maturity:         {scores['maturity_level']}")

    # Print report summary
    print(f"\n{orch.reporter.export_summary()}")
    print("\n  Done! Start the server with: python run.py\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberTwin SOC Platform")
    parser.add_argument("--demo", action="store_true", help="Run a demo simulation")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    else:
        start_server()
