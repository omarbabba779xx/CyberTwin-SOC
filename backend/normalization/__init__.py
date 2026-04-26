"""
CyberTwin SOC - Event Normalization (Phase 4)
================================================
Maps heterogeneous log sources (Windows EventLog, Sysmon, Linux syslog,
AWS CloudTrail, JSON-over-HTTP, ...) into a single OCSF-compatible
schema so detection rules can run against any source uniformly.

Primary schema: OCSF v1.x (Open Cybersecurity Schema Framework).
Secondary compatibility: ECS (Elastic Common Schema) where useful.

Public surface:
    NormalizedEvent       - the canonical OCSF-shaped dataclass
    Normalizer            - dispatches to the right mapper
    register_mapper       - plug a new source-type mapper
    list_supported        - introspection
"""

from .schema import (
    NormalizedEvent, EventCategory, EventSeverity,
    UserRef, EndpointRef, ProcessRef, FileRef, NetworkRef, CloudRef,
)
from .normalizer import Normalizer, register_mapper, list_supported

__all__ = [
    "NormalizedEvent",
    "EventCategory", "EventSeverity",
    "UserRef", "EndpointRef", "ProcessRef", "FileRef", "NetworkRef", "CloudRef",
    "Normalizer", "register_mapper", "list_supported",
]
