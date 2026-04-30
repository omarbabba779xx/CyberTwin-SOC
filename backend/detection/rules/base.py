"""DetectionRule dataclass — schema for detection rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class DetectionRule:
    """A single detection rule applied by the engine against incoming logs.

    The first block of fields is required for the rule engine. The second
    block (Phase 2 metadata) is optional and used by the Detection Coverage
    Center to compute status, gaps, and recommendations. Defaults are set
    so existing rules continue to work without modification.
    """

    rule_id: str
    name: str
    description: str
    severity: str  # info | low | medium | high | critical
    tactic: str  # MITRE ATT&CK tactic
    technique_id: str
    technique_name: str
    condition: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None
    enabled: bool = True

    # ---- Phase 2 metadata (Detection Coverage Center) ----------------------
    status: str = "stable"          # experimental | stable | deprecated
    version: str = "1.0.0"
    author: str = "cybertwin"
    required_logs: list[str] = field(default_factory=list)     # e.g. ["windows_event"]
    required_fields: list[str] = field(default_factory=list)   # e.g. ["process.name"]
    false_positives: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.85        # 0.0 - 1.0
