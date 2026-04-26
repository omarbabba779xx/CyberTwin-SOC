"""OCSF-compatible canonical event schema."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class EventCategory(str, Enum):
    """Top-level OCSF activity categories used in detection rules."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    DNS = "dns"
    EMAIL = "email"
    SECURITY = "security"
    AUDIT = "audit"
    CLOUD = "cloud"
    UNKNOWN = "unknown"


class EventSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Lightweight reference objects (a subset of OCSF Common Object Reference)
# ---------------------------------------------------------------------------

@dataclass
class UserRef:
    name: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
    type: Optional[str] = None        # human | service | system

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class EndpointRef:
    hostname: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    type: Optional[str] = None        # workstation | server | dc | container

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ProcessRef:
    name: Optional[str] = None
    command_line: Optional[str] = None
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    integrity_level: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class FileRef:
    path: Optional[str] = None
    name: Optional[str] = None
    size: Optional[int] = None
    hash_sha256: Optional[str] = None
    operation: Optional[str] = None    # create | modify | delete | read | execute

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class NetworkRef:
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None    # inbound | outbound | lateral
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class CloudRef:
    provider: Optional[str] = None     # aws | azure | gcp
    region: Optional[str] = None
    account_id: Optional[str] = None
    resource_arn: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ---------------------------------------------------------------------------
# The canonical event
# ---------------------------------------------------------------------------

@dataclass
class NormalizedEvent:
    """A source-agnostic, OCSF-shaped event ready for the detection engine."""

    # Required envelope
    event_id: str
    timestamp: str                              # ISO-8601 UTC
    source_type: str                            # windows_event | sysmon | syslog | ...
    category: str = EventCategory.UNKNOWN.value
    activity: str = ""                          # OCSF activity name
    severity: str = EventSeverity.INFO.value
    tenant_id: str = "default"

    # Common refs (all optional)
    user: UserRef = field(default_factory=UserRef)
    src_endpoint: EndpointRef = field(default_factory=EndpointRef)
    dst_endpoint: EndpointRef = field(default_factory=EndpointRef)
    process: ProcessRef = field(default_factory=ProcessRef)
    file: FileRef = field(default_factory=FileRef)
    network: NetworkRef = field(default_factory=NetworkRef)
    cloud: CloudRef = field(default_factory=CloudRef)

    # Free-form
    message: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    # ---- Conversion helpers ----------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a clean dict (no empty refs) suitable for JSON / detection."""
        out: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "category": self.category,
            "activity": self.activity,
            "severity": self.severity,
            "tenant_id": self.tenant_id,
            "message": self.message,
        }
        for ref_name, ref in (
            ("user", self.user), ("src_endpoint", self.src_endpoint),
            ("dst_endpoint", self.dst_endpoint), ("process", self.process),
            ("file", self.file), ("network", self.network),
            ("cloud", self.cloud),
        ):
            d = ref.to_dict()
            if d:
                out[ref_name] = d
        if self.raw:
            out["raw"] = self.raw
        return out

    def to_engine_dict(self) -> dict[str, Any]:
        """Flat dict shaped for backend.detection.engine compatibility.

        The existing detection rules expect fields like `process_name`,
        `command_line`, `src_host`, `affected_user`, etc. We translate
        the canonical OCSF event into that shape so a normalised event
        from any source can be fed to the legacy DetectionEngine without
        rewriting the rules. This is the integration glue between Phase 4
        ingestion and the existing detection pipeline.
        """
        d: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "category": self.category,
            "event_type": self.activity or self.category,
            "description": self.message,
            "tenant_id": self.tenant_id,
        }
        if self.user.name:
            d["user"] = self.user.name
            d["username"] = self.user.name
        if self.src_endpoint.hostname:
            d["host"] = self.src_endpoint.hostname
            d["src_host"] = self.src_endpoint.hostname
        if self.src_endpoint.ip:
            d["source_ip"] = self.src_endpoint.ip
            d["src_ip"] = self.src_endpoint.ip
        if self.dst_endpoint.ip:
            d["dest_ip"] = self.dst_endpoint.ip
        if self.process.name:
            d["process_name"] = self.process.name
        if self.process.command_line:
            d["command_line"] = self.process.command_line
        if self.process.parent_name:
            d["parent_process"] = self.process.parent_name
        if self.file.path:
            d["file_path"] = self.file.path
        if self.network.dst_port:
            d["dest_port"] = self.network.dst_port
        if self.network.bytes_sent:
            d["bytes_sent"] = self.network.bytes_sent
        return d


def now_iso() -> str:
    """UTC ISO-8601 timestamp for use as default."""
    return datetime.now(timezone.utc).isoformat()
