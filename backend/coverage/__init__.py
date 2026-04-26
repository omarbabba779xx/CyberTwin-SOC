"""
CyberTwin SOC - Detection Coverage Center
==========================================
Computes the *real* detection coverage status for every MITRE ATT&CK
technique by joining four data sources:

  1. The MITRE catalog (622 techniques)        -> backend.mitre.attack_data
  2. Detection rules                            -> backend.detection.rules
  3. Attack scenarios                           -> backend.simulation.attack_engine
  4. Recent simulation results                  -> backend.cache (cache:result:*)

Each technique is classified into one of 8 honest statuses:

  not_covered                Catalog only, no rule, no scenario.
  rule_exists                Rule exists but technique never simulated.
  rule_exists_untested       Rule exists, scenario covers it, never run yet.
  tested_and_detected        Recent simulation produced an alert.
  tested_but_failed          Recent simulation ran but rule did not fire.
  noisy                      Rule fires often AND has FP feedback (Phase 3+).
  needs_data_source          Rule exists but its required_logs are unavailable.
  not_applicable             Marked OOS by the operator.

The output is intentionally honest: the prompt mandates that we never claim
coverage just because the catalog is loaded.
"""

from .models import (
    TechniqueStatus,
    TechniqueCoverage,
    CoverageSummary,
    Gap,
)
from .calculator import CoverageCalculator
from .gap_analyzer import GapAnalyzer

__all__ = [
    "TechniqueStatus",
    "TechniqueCoverage",
    "CoverageSummary",
    "Gap",
    "CoverageCalculator",
    "GapAnalyzer",
]
