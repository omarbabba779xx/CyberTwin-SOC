"""Source-specific mappers that convert raw events to NormalizedEvent.

Each mapper is a callable (raw_event_dict) -> NormalizedEvent. Mappers
are pure functions; they do not raise on missing fields, they fall back
to None / empty.
"""

from __future__ import annotations

import re
import uuid

from .schema import (
    CloudRef, EndpointRef, EventCategory, EventSeverity, FileRef,
    NetworkRef, NormalizedEvent, ProcessRef, UserRef, now_iso,
)


def _ensure_id(raw: dict) -> str:
    return (raw.get("event_id")
            or raw.get("id")
            or raw.get("EventRecordID")
            or f"evt-{uuid.uuid4().hex[:12]}")


def _ensure_ts(raw: dict, *fields: str) -> str:
    for f in fields:
        v = raw.get(f)
        if v:
            return str(v)
    for v in (raw.get("timestamp"), raw.get("@timestamp"),
              raw.get("eventTime"), raw.get("TimeCreated"),
              raw.get("UtcTime")):
        if v:
            return str(v)
    return now_iso()


# ---------------------------------------------------------------------------
# Windows Event Log
# ---------------------------------------------------------------------------

# Subset of EventIDs we care about. Map -> (category, activity, severity).
_WINDOWS_EID_MAP = {
    4624: (EventCategory.AUTHENTICATION, "logon_success", EventSeverity.INFO),
    4625: (EventCategory.AUTHENTICATION, "logon_failure", EventSeverity.MEDIUM),
    4634: (EventCategory.AUTHENTICATION, "logoff", EventSeverity.INFO),
    4648: (EventCategory.AUTHENTICATION, "logon_explicit", EventSeverity.LOW),
    4672: (EventCategory.SECURITY, "special_logon", EventSeverity.LOW),
    4688: (EventCategory.PROCESS, "process_create", EventSeverity.INFO),
    4689: (EventCategory.PROCESS, "process_terminate", EventSeverity.INFO),
    4720: (EventCategory.SECURITY, "user_created", EventSeverity.MEDIUM),
    4732: (EventCategory.SECURITY, "group_member_add", EventSeverity.MEDIUM),
    4740: (EventCategory.SECURITY, "account_locked", EventSeverity.MEDIUM),
    4768: (EventCategory.AUTHENTICATION, "kerberos_tgt", EventSeverity.LOW),
    4769: (EventCategory.AUTHENTICATION, "kerberos_tgs", EventSeverity.LOW),
    7045: (EventCategory.SECURITY, "service_install", EventSeverity.HIGH),
    1102: (EventCategory.AUDIT, "audit_log_cleared", EventSeverity.HIGH),
}


def map_windows_event(raw: dict) -> NormalizedEvent:
    """Map a Windows EventLog record to NormalizedEvent.

    Accepts both the verbose XML-flattened JSON shape (EventData/System
    nested) and the modern winlogbeat-style shape.
    """
    # Some shippers nest under "Event" or "winlog"; flatten what we can.
    src = raw.get("Event") or raw.get("winlog") or raw
    event_data = src.get("EventData") or src.get("event_data") or src
    system = src.get("System") or src.get("system") or src

    eid_raw = (system.get("EventID") or src.get("event_id")
               or src.get("EventID") or 0)
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", 0)
    try:
        eid = int(eid_raw)
    except (ValueError, TypeError):
        eid = 0

    cat, activity, sev = _WINDOWS_EID_MAP.get(
        eid, (EventCategory.UNKNOWN, f"event_{eid}", EventSeverity.INFO),
    )

    user = UserRef(
        name=event_data.get("TargetUserName") or event_data.get("SubjectUserName"),
        domain=event_data.get("TargetDomainName") or event_data.get("SubjectDomainName"),
        sid=event_data.get("TargetUserSid") or event_data.get("SubjectUserSid"),
    )

    endpoint = EndpointRef(
        hostname=system.get("Computer") or src.get("host", {}).get("hostname"),
        ip=event_data.get("IpAddress") or event_data.get("WorkstationName"),
        os="Windows",
    )

    process = ProcessRef(
        name=event_data.get("NewProcessName") or event_data.get("ProcessName"),
        command_line=event_data.get("CommandLine") or event_data.get("ProcessCommandLine"),
        pid=int(event_data["ProcessId"]) if str(event_data.get("ProcessId", "")).isdigit() else None,
        parent_name=event_data.get("ParentProcessName"),
        parent_pid=int(event_data["ParentProcessId"]) if str(event_data.get("ParentProcessId", "")).isdigit() else None,
    )

    return NormalizedEvent(
        event_id=_ensure_id(src),
        timestamp=_ensure_ts(system, "TimeCreated", "SystemTime"),
        source_type="windows_event",
        category=cat.value,
        activity=activity,
        severity=sev.value,
        user=user,
        src_endpoint=endpoint,
        process=process,
        message=src.get("Message") or f"Windows Event ID {eid}",
        raw=src,
    )


# ---------------------------------------------------------------------------
# Sysmon (Microsoft-Windows-Sysmon Operational)
# ---------------------------------------------------------------------------

_SYSMON_EID_MAP = {
    1: (EventCategory.PROCESS, "process_create", EventSeverity.INFO),
    3: (EventCategory.NETWORK, "network_connection", EventSeverity.LOW),
    7: (EventCategory.PROCESS, "image_loaded", EventSeverity.LOW),
    8: (EventCategory.PROCESS, "remote_thread_create", EventSeverity.HIGH),
    10: (EventCategory.PROCESS, "process_access", EventSeverity.HIGH),
    11: (EventCategory.FILE, "file_create", EventSeverity.LOW),
    12: (EventCategory.PROCESS, "registry_event", EventSeverity.LOW),
    13: (EventCategory.PROCESS, "registry_value_set", EventSeverity.LOW),
    22: (EventCategory.DNS, "dns_query", EventSeverity.INFO),
    23: (EventCategory.FILE, "file_delete", EventSeverity.MEDIUM),
}


def map_sysmon(raw: dict) -> NormalizedEvent:
    src = raw.get("Event") or raw.get("winlog") or raw
    event_data = src.get("EventData") or src.get("event_data") or src
    system = src.get("System") or src.get("system") or src

    eid_raw = system.get("EventID") or event_data.get("EventID") or 0
    if isinstance(eid_raw, dict):
        eid_raw = eid_raw.get("#text", 0)
    try:
        eid = int(eid_raw)
    except (ValueError, TypeError):
        eid = 0

    cat, activity, sev = _SYSMON_EID_MAP.get(
        eid, (EventCategory.UNKNOWN, f"sysmon_{eid}", EventSeverity.INFO),
    )

    user = UserRef(name=event_data.get("User"))
    endpoint = EndpointRef(
        hostname=system.get("Computer"),
        ip=event_data.get("SourceIp"),
        os="Windows",
    )
    process = ProcessRef(
        name=event_data.get("Image"),
        command_line=event_data.get("CommandLine"),
        pid=int(event_data["ProcessId"]) if str(event_data.get("ProcessId", "")).isdigit() else None,
        parent_name=event_data.get("ParentImage"),
        parent_pid=int(event_data["ParentProcessId"]) if str(event_data.get("ParentProcessId", "")).isdigit() else None,
        hash_sha256=event_data.get("Hashes", "").split("SHA256=")[-1].split(",")[0]
        if "SHA256=" in (event_data.get("Hashes") or "") else None,
    )
    network = NetworkRef(
        src_ip=event_data.get("SourceIp"),
        src_port=int(event_data["SourcePort"]) if str(event_data.get("SourcePort", "")).isdigit() else None,
        dst_ip=event_data.get("DestinationIp"),
        dst_port=int(event_data["DestinationPort"]) if str(event_data.get("DestinationPort", "")).isdigit() else None,
        protocol=event_data.get("Protocol"),
    )
    file_ref = FileRef(
        path=event_data.get("TargetFilename") or event_data.get("Image"),
        hash_sha256=process.hash_sha256,
    )

    return NormalizedEvent(
        event_id=_ensure_id(src),
        timestamp=_ensure_ts(event_data, "UtcTime", "TimeCreated"),
        source_type="sysmon",
        category=cat.value,
        activity=activity,
        severity=sev.value,
        user=user,
        src_endpoint=endpoint,
        process=process,
        network=network,
        file=file_ref,
        message=src.get("Message") or f"Sysmon Event ID {eid}",
        raw=src,
    )


# ---------------------------------------------------------------------------
# Linux syslog (RFC 3164 + RFC 5424 simplified)
# ---------------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?\s*"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)?\s*"
    r"(?P<host>\S+)?\s+"
    r"(?P<app>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.+)$"
)

_SYSLOG_AUTH_FAIL = re.compile(
    r"(?:Failed password|authentication failure)"
    r"(?:.*?for\s+(?:invalid user\s+)?(?P<user>\S+))?"
    r"(?:.*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?",
    re.IGNORECASE,
)

_SYSLOG_AUTH_OK = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)


def map_syslog(raw: dict) -> NormalizedEvent:
    """Parse a single syslog line.

    Accepts either {"line": "..."} or already partially parsed {"host":..., "message":...}.
    """
    line = raw.get("line") or raw.get("message") or ""
    m = _SYSLOG_RE.match(line.strip()) if line else None

    host = (m.group("host") if m else None) or raw.get("host", "")
    app = (m.group("app") if m else None) or raw.get("app", "")
    msg = (m.group("msg") if m else None) or line

    cat = EventCategory.AUDIT
    activity = "syslog"
    sev = EventSeverity.INFO
    user_ref = UserRef()
    network_ref = NetworkRef()

    auth_fail = _SYSLOG_AUTH_FAIL.search(msg) if msg else None
    auth_ok = _SYSLOG_AUTH_OK.search(msg) if msg else None

    if auth_fail:
        cat = EventCategory.AUTHENTICATION
        activity = "logon_failure"
        sev = EventSeverity.MEDIUM
        user_ref.name = auth_fail.group("user")
        ip = auth_fail.group("ip")
        if ip:
            network_ref.src_ip = ip
    elif auth_ok:
        cat = EventCategory.AUTHENTICATION
        activity = "logon_success"
        sev = EventSeverity.INFO
        user_ref.name = auth_ok.group("user")
        network_ref.src_ip = auth_ok.group("ip")

    return NormalizedEvent(
        event_id=_ensure_id(raw),
        timestamp=_ensure_ts(raw, "ts") or now_iso(),
        source_type="syslog",
        category=cat.value,
        activity=activity,
        severity=sev.value,
        user=user_ref,
        src_endpoint=EndpointRef(hostname=host, ip=network_ref.src_ip, os="linux"),
        process=ProcessRef(name=app or None),
        network=network_ref,
        message=msg,
        raw={"line": line, **{k: v for k, v in raw.items() if k != "line"}},
    )


# ---------------------------------------------------------------------------
# AWS CloudTrail
# ---------------------------------------------------------------------------

def map_cloudtrail(raw: dict) -> NormalizedEvent:
    """Map a CloudTrail event record."""
    name = raw.get("eventName", "")
    src = raw.get("sourceIPAddress", "")
    user_ident = raw.get("userIdentity") or {}

    sev = EventSeverity.LOW
    cat = EventCategory.CLOUD
    activity = name or "cloudtrail_event"
    if name in ("ConsoleLogin", "AssumeRole"):
        cat = EventCategory.AUTHENTICATION
        if raw.get("errorCode"):
            sev = EventSeverity.MEDIUM
            activity = "logon_failure"
        else:
            activity = "logon_success"
    elif name in ("CreateUser", "AttachUserPolicy", "PutUserPolicy"):
        cat = EventCategory.SECURITY
        sev = EventSeverity.MEDIUM
    elif name == "DeleteTrail" or name == "StopLogging":
        cat = EventCategory.AUDIT
        activity = "audit_log_cleared"
        sev = EventSeverity.HIGH

    return NormalizedEvent(
        event_id=raw.get("eventID") or _ensure_id(raw),
        timestamp=_ensure_ts(raw, "eventTime"),
        source_type="cloudtrail",
        category=cat.value,
        activity=activity,
        severity=sev.value,
        user=UserRef(
            name=user_ident.get("userName") or user_ident.get("arn"),
            type=user_ident.get("type"),
        ),
        src_endpoint=EndpointRef(ip=src),
        cloud=CloudRef(
            provider="aws",
            region=raw.get("awsRegion"),
            account_id=raw.get("recipientAccountId"),
            resource_arn=user_ident.get("arn"),
        ),
        message=f"AWS {name} by {user_ident.get('userName', 'unknown')}",
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Generic JSON: best-effort fallback when source_type is unknown.
# ---------------------------------------------------------------------------

def map_generic_json(raw: dict) -> NormalizedEvent:
    """Best-effort mapping for arbitrary JSON events.

    Looks for common field names (`user`, `host`, `process_name`...) so a
    self-described event from any home-grown shipper still becomes useful.
    """
    return NormalizedEvent(
        event_id=_ensure_id(raw),
        timestamp=_ensure_ts(raw),
        source_type=raw.get("source_type", "json"),
        category=raw.get("category", EventCategory.UNKNOWN.value),
        activity=raw.get("activity") or raw.get("event_type", "unknown"),
        severity=raw.get("severity", EventSeverity.INFO.value),
        user=UserRef(name=raw.get("user") or raw.get("username")),
        src_endpoint=EndpointRef(
            hostname=raw.get("host") or raw.get("hostname"),
            ip=raw.get("source_ip") or raw.get("src_ip"),
        ),
        dst_endpoint=EndpointRef(ip=raw.get("dest_ip") or raw.get("dst_ip")),
        process=ProcessRef(
            name=raw.get("process_name") or raw.get("process"),
            command_line=raw.get("command_line"),
        ),
        file=FileRef(path=raw.get("file_path")),
        network=NetworkRef(
            src_ip=raw.get("source_ip"),
            dst_ip=raw.get("dest_ip"),
            dst_port=int(raw["dest_port"]) if str(raw.get("dest_port", "")).isdigit() else None,
        ),
        message=raw.get("message") or raw.get("description", ""),
        raw=raw,
    )
