"""Detection rules package — public API.

Re-exports the rule schema and the pre-built rule catalogue so that
existing imports (``from backend.detection.rules import DetectionRule,
DETECTION_RULES``) keep working unchanged after the package split.
"""

from .base import DetectionRule
from .catalogue import DETECTION_RULES

__all__ = ["DetectionRule", "DETECTION_RULES"]
