"""CyberTwin SOC — AI Analyst Module.

Rule-based Natural Language Generation engine that produces professional,
analyst-quality incident reports without requiring any external API.

The :class:`AIAnalyst` class examines simulation artefacts (alerts, incidents,
scores, MITRE coverage, timeline, logs) and generates a comprehensive
analysis dict that reads as if a Level 3 SOC analyst wrote it.

This package is the result of splitting the original 1375-line
``backend/ai_analyst.py`` module into topical sub-modules. The public API is
preserved: ``from backend.ai_analyst import AIAnalyst`` continues to work.
"""

from .core import AIAnalyst

__all__ = ["AIAnalyst"]
