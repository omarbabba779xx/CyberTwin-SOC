"""
Data models for the CyberTwin SOC telemetry / log generator module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class LogSeverity(str, Enum):
    """Severity levels for log events, aligned with common SIEM conventions."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(str, Enum):
    """Categories of log sources observed across the simulated environment."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    FIREWALL = "firewall"
    DNS = "dns"
    WEB_ACCESS = "web_access"
    EMAIL = "email"
    APPLICATION = "application"
    DATABASE = "database"
    SECURITY = "security"
    IDS = "ids"


@dataclass
class LogEvent:
    """A single telemetry / log entry produced by the simulation environment.

    Fields mirror common SIEM normalised schemas so that downstream detection
    rules can operate on them without additional transformation.
    """

    timestamp: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    log_source: str = LogSource.SECURITY.value
    event_type: str = ""
    severity: str = LogSeverity.INFO.value
    src_host: str = ""
    src_ip: str = ""
    dst_host: str = ""
    dst_ip: str = ""
    user: str = ""
    process_name: str = ""
    command_line: str = ""
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    technique_id: Optional[str] = None
    scenario_id: Optional[str] = None
    is_malicious: bool = False
    windows_event_id: Optional[int] = None
    sysmon_event_id: Optional[int] = None
    event_source: str = ""
    event_id_description: str = ""

    # ---- helpers ----

    def to_dict(self) -> dict[str, Any]:
        """Return a plain-dict representation suitable for JSON serialisation."""
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "log_source": self.log_source,
            "event_type": self.event_type,
            "severity": self.severity,
            "src_host": self.src_host,
            "src_ip": self.src_ip,
            "dst_host": self.dst_host,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "description": self.description,
            "raw_data": self.raw_data,
            "tags": self.tags,
            "technique_id": self.technique_id,
            "scenario_id": self.scenario_id,
            "is_malicious": self.is_malicious,
            "windows_event_id": self.windows_event_id,
            "sysmon_event_id": self.sysmon_event_id,
            "event_source": self.event_source,
            "event_id_description": self.event_id_description,
        }
