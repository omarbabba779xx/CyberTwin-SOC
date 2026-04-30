"""
CyberTwin SOC - Operational SOC module (Phase 3)
==================================================
Provides the workflow primitives a real SOC needs on top of detection:

  - Alert feedback   (TP / FP / Benign / Duplicate / NeedsMoreData / Escalated / Closed)
  - Case management  (Alert -> Incident -> Case + Evidence + Comments + Tasks)
  - Suppressions     (rule/user/host scoped, MUST have an expiration)

Local/demo persistence is SQLite under data/cybertwin.db, with every workflow
row tenant-scoped. Tables are created lazily by `init_soc_tables()`.
"""

from .database import init_soc_tables
from .models import (
    AlertVerdict, CaseStatus, CaseSeverity, SuppressionScope,
    AlertFeedback, Case, CaseComment, CaseEvidence, Suppression,
)
from .feedback import (
    record_feedback, list_feedback, feedback_summary, list_noisy_rules,
)
from .cases import (
    create_case, get_case, list_cases, update_case, close_case, assign_case,
    add_comment, add_evidence,
)
from .suppressions import (
    create_suppression, list_suppressions, delete_suppression,
    is_alert_suppressed,
)

__all__ = [
    "init_soc_tables",
    "AlertVerdict", "CaseStatus", "CaseSeverity", "SuppressionScope",
    "AlertFeedback", "Case", "CaseComment", "CaseEvidence", "Suppression",
    "record_feedback", "list_feedback", "feedback_summary", "list_noisy_rules",
    "create_case", "get_case", "list_cases", "update_case", "close_case",
    "assign_case", "add_comment", "add_evidence",
    "create_suppression", "list_suppressions", "delete_suppression",
    "is_alert_suppressed",
]
