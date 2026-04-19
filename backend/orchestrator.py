"""
CyberTwin SOC - Simulation Orchestrator
========================================
Coordinates the full simulation pipeline: environment loading,
normal activity generation, attack execution, telemetry processing,
detection analysis, scoring, and AI-powered incident analysis.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from .simulation.environment import EnvironmentBuilder
from .simulation.normal_activity import NormalActivityGenerator
from .simulation.attack_engine import AttackScenarioEngine
from .telemetry.log_generator import TelemetryEngine
from .detection.engine import DetectionEngine
from .scoring import ScoringEngine
from .reports.generator import ReportGenerator
from .ai_analyst import AIAnalyst


class SimulationOrchestrator:
    """Main orchestrator that runs the complete simulation pipeline.

    The pipeline follows these steps:
    1. Load digital twin environment (hosts, users, network)
    2. Generate normal baseline activity
    3. Execute attack scenario phases
    4. Process events through telemetry engine
    5. Run detection rules and correlate incidents
    6. Calculate multi-dimensional security scores
    7. Generate AI analyst narrative report

    Usage::

        orch = SimulationOrchestrator()
        orch.initialise()
        result = orch.run_simulation("sc-phishing-001")
    """

    def __init__(self) -> None:
        """Initialize all sub-modules with default configuration."""
        self.environment = EnvironmentBuilder()
        self.normal_gen = None  # set after env loads
        self.attack_engine = AttackScenarioEngine()
        self.telemetry = TelemetryEngine()
        self.detection = DetectionEngine()
        self.scoring = ScoringEngine()
        self.reporter = ReportGenerator()
        self.ai_analyst = AIAnalyst()

        self._last_result: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def initialise(self) -> None:
        """Load environment data and scenario definitions."""
        self.environment.load()
        self.normal_gen = NormalActivityGenerator(self.environment, seed=42)
        self.attack_engine.load_scenarios()

    # ------------------------------------------------------------------
    # Full simulation
    # ------------------------------------------------------------------

    def run_simulation(
        self,
        scenario_id: str,
        duration_minutes: int = 60,
        normal_intensity: str = "normal",
        start_time: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Execute a complete attack simulation.

        Args:
            scenario_id: Identifier of the attack scenario (e.g., 'sc-phishing-001')
            duration_minutes: Duration of the simulation window in minutes
            normal_intensity: Intensity of normal background activity ('low', 'normal', 'high')
            start_time: Override the simulation start timestamp

        Returns:
            dict with keys: logs, alerts, incidents, scores, report, ai_analysis, timeline

        Raises:
            ValueError: If scenario_id is not found
        """
        if self.normal_gen is None:
            self.initialise()

        # Default to a mid-morning time during work hours for realistic simulation
        start = start_time or datetime.now().replace(hour=9, minute=30, second=0, microsecond=0)
        scenario = self.attack_engine.get_scenario(scenario_id)
        if scenario is None:
            raise ValueError(f"Unknown scenario: {scenario_id}")

        # Step 1 — Generate normal (benign) activity
        normal_events = self.normal_gen.generate_activity(
            duration_minutes=duration_minutes,
            intensity=normal_intensity,
            start_time=start,
        )

        # Step 2 — Generate attack events
        attack_events = self.attack_engine.generate_attack_events(
            scenario_id=scenario_id,
            start_time=start,
        )

        # Step 3 — Merge & generate telemetry
        self.telemetry.clear()  # Reset logs from any previous simulation
        all_events = sorted(
            normal_events + attack_events,
            key=lambda e: e.get("timestamp", ""),
        )
        log_objects = self.telemetry.generate_logs(all_events)
        log_dicts = [l.to_dict() for l in log_objects]

        # Step 4 — Run detection
        alerts = self.detection.analyse(log_dicts)
        incidents = self.detection.correlate_incidents(alerts)
        mitre_coverage = self.detection.get_mitre_coverage()

        # Step 5 — Calculate scores
        scores = self.scoring.calculate_scores(
            scenario=scenario,
            alerts=alerts,
            logs=log_dicts,
        )

        # Step 6 — Generate report
        env_raw = self.environment.to_dict()
        # Report generator expects hosts as a list, not a dict
        env_dict = {
            **env_raw,
            "hosts": list(env_raw.get("hosts", {}).values()) if isinstance(env_raw.get("hosts"), dict) else env_raw.get("hosts", []),
        }
        logs_stats = self.telemetry.get_statistics()
        timeline = [
            {
                "timestamp": l.get("timestamp", ""),
                "event_type": l.get("event_type", ""),
                "src_host": l.get("src_host", ""),
                "user": l.get("user", ""),
                "description": l.get("description", ""),
                "severity": l.get("severity", ""),
                "is_malicious": l.get("is_malicious", False),
                "technique_id": l.get("technique_id"),
            }
            for l in log_dicts
        ]

        report = self.reporter.generate_report(
            scenario=scenario,
            environment=env_dict,
            alerts=alerts,
            incidents=incidents,
            mitre_coverage=mitre_coverage,
            scores=scores,
            logs_stats=logs_stats,
            timeline=timeline,
        )

        # Step 7 — AI Analyst narrative generation
        ai_analysis = self.ai_analyst.analyse_incident(
            scenario=scenario,
            alerts=alerts,
            incidents=incidents,
            scores=scores,
            mitre_coverage=mitre_coverage,
            timeline=timeline,
            logs_stats=logs_stats,
        )

        self._last_result = {
            "scenario": scenario,
            "environment": env_dict,
            "normal_events_count": len(normal_events),
            "attack_events_count": len(attack_events),
            "total_events": len(all_events),
            "total_logs": len(log_dicts),
            "logs": log_dicts,
            "alerts": alerts,
            "incidents": incidents,
            "mitre_coverage": mitre_coverage,
            "scores": scores,
            "report": report,
            "ai_analysis": ai_analysis,
            "timeline": timeline,
            "logs_statistics": logs_stats,
        }

        return self._last_result

    def get_last_result(self) -> dict[str, Any] | None:
        """Return the result dict from the most recent simulation run, or None."""
        return self._last_result
