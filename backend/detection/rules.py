"""
Detection rules for the CyberTwin SOC detection engine.

Each rule defines a condition function that receives a list of log-event dicts
and returns the subset of events that matched the rule's logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
]


_ts_cache: dict[str, datetime] = {}


def _parse_ts(ts_str: str) -> datetime:
    """Best-effort timestamp parsing with cache."""
    if ts_str in _ts_cache:
        return _ts_cache[ts_str]
    for fmt in _TS_FORMATS:
        try:
            result = datetime.strptime(ts_str, fmt)
            _ts_cache[ts_str] = result
            return result
        except (ValueError, TypeError):
            continue
    _ts_cache[ts_str] = datetime.min
    return datetime.min


def _events_in_window(
    events: list[dict[str, Any]], window_seconds: int
) -> list[list[dict[str, Any]]]:
    """Group events into sliding windows of *window_seconds*.

    Returns a list of groups where each group contains events that fall
    within the same time window.  Optimised to parse timestamps once.
    """
    if not events:
        return []

    # Parse timestamps once, pair with event, then sort
    paired = []
    for e in events:
        ts = _parse_ts(e.get("timestamp", ""))
        paired.append((ts, e))
    paired.sort(key=lambda x: x[0])

    groups: list[list[dict[str, Any]]] = []
    n = len(paired)
    for i in range(n):
        anchor_ts = paired[i][0]
        window_end = anchor_ts + timedelta(seconds=window_seconds)
        group = [paired[i][1]]
        for j in range(i + 1, n):
            if paired[j][0] <= window_end:
                group.append(paired[j][1])
            else:
                break  # sorted, so no more events in window
        if len(group) > 1:
            groups.append(group)

    return groups


# RFC 1918 / private-address prefixes
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")


def _is_external_ip(ip: str) -> bool:
    """Return True if *ip* is not in a well-known private range."""
    if not ip:
        return False
    return not ip.startswith(_PRIVATE_PREFIXES)


# ---------------------------------------------------------------------------
# Rule condition functions
# ---------------------------------------------------------------------------

def _multiple_failed_logins(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect > 5 failed login events from the same user within 5 minutes."""
    failed = [
        e for e in events
        if e.get("log_source") == "authentication"
        and e.get("event_type", "").lower() in ("login_failure", "failed_login",
                                                "authentication_failure", "logon_failure")
    ]
    # Group by user
    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in failed:
        by_user.setdefault(e.get("user", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for user_events in by_user.values():
        for group in _events_in_window(user_events, 300):
            if len(group) > 5:
                matched.extend(group)
    return matched


def _login_after_failures(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect a successful login preceded by multiple failures for same user."""
    auth_events = [
        e for e in events
        if e.get("log_source") == "authentication"
    ]
    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in auth_events:
        by_user.setdefault(e.get("user", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for user_events in by_user.values():
        sorted_evts = sorted(user_events, key=lambda e: _parse_ts(e.get("timestamp", "")))
        fail_count = 0
        for e in sorted_evts:
            etype = e.get("event_type", "").lower()
            if etype in ("login_failure", "failed_login", "authentication_failure", "logon_failure"):
                fail_count += 1
            elif etype in ("login_success", "successful_login", "authentication_success", "logon_success"):
                if fail_count >= 3:
                    matched.append(e)
                fail_count = 0
    return matched


def _login_external_ip(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect logins originating from an external / unusual IP address."""
    return [
        e for e in events
        if e.get("log_source") == "authentication"
        and e.get("event_type", "").lower() in ("login_success", "successful_login",
                                                "authentication_success", "logon_success")
        and _is_external_ip(e.get("src_ip", ""))
    ]


def _off_hours_login(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect successful logins outside normal business hours (before 6 AM or after 10 PM)."""
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") != "authentication":
            continue
        etype = e.get("event_type", "").lower()
        if etype not in ("login_success", "successful_login", "authentication_success", "logon_success"):
            continue
        ts = _parse_ts(e.get("timestamp", ""))
        if ts.hour < 6 or ts.hour >= 22:
            matched.append(e)
    return matched


def _port_scan(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect > 10 distinct destination ports from the same source IP in 60 seconds."""
    network = [
        e for e in events
        if e.get("log_source") in ("network", "firewall", "ids")
    ]
    by_src: dict[str, list[dict[str, Any]]] = {}
    for e in network:
        by_src.setdefault(e.get("src_ip", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for src_events in by_src.values():
        for group in _events_in_window(src_events, 60):
            ports = {
                e.get("raw_data", {}).get("dst_port")
                or e.get("raw_data", {}).get("destination_port")
                for e in group
            }
            ports.discard(None)
            if len(ports) > 10:
                matched.extend(group)
    return matched


def _ssh_brute_force(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect > 20 SSH authentication failures from same source in 10 minutes."""
    ssh_fail = [
        e for e in events
        if e.get("log_source") == "authentication"
        and e.get("event_type", "").lower() in ("login_failure", "failed_login",
                                                "authentication_failure", "logon_failure")
        and (
            e.get("raw_data", {}).get("protocol", "").lower() == "ssh"
            or e.get("raw_data", {}).get("service", "").lower() == "ssh"
            or "ssh" in e.get("description", "").lower()
            or "ssh" in " ".join(e.get("tags", [])).lower()
        )
    ]
    by_src: dict[str, list[dict[str, Any]]] = {}
    for e in ssh_fail:
        by_src.setdefault(e.get("src_ip", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for src_events in by_src.values():
        for group in _events_in_window(src_events, 600):
            if len(group) > 20:
                matched.extend(group)
    return matched


def _privilege_escalation(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect privilege escalation commands (sudo, su, runas, etc.)."""
    escalation_patterns = re.compile(
        r"\b(sudo|su\s|runas|pkexec|doas|newgrp|setuid)\b", re.IGNORECASE
    )
    return [
        e for e in events
        if e.get("log_source") in ("process", "security")
        and escalation_patterns.search(e.get("command_line", ""))
    ]


def _suspicious_process(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect suspicious process execution: reverse shells, encoded commands."""
    suspicious_patterns = re.compile(
        r"(nc\s+-e|ncat\s+-e|bash\s+-i|/dev/tcp/"
        r"|python\s+-c\s+.*socket|perl\s+-e\s+.*socket"
        r"|powershell.*-e(nc(oded)?c(ommand)?)?[\s\r]"
        r"|certutil.*-urlcache"
        r"|mshta\s|regsvr32\s.*\/s.*\/i"
        r"|base64\s+-d|base64\s+--decode"
        r"|wget\s+.*\|\s*(ba)?sh"
        r"|curl\s+.*\|\s*(ba)?sh)",
        re.IGNORECASE,
    )
    return [
        e for e in events
        if e.get("log_source") in ("process", "security")
        and suspicious_patterns.search(e.get("command_line", ""))
    ]


def _large_outbound_transfer(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect outbound data transfers exceeding 100 MB."""
    threshold_bytes = 100 * 1024 * 1024  # 100 MB
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("network", "firewall"):
            continue
        raw = e.get("raw_data", {})
        bytes_out = raw.get("bytes_out", 0) or raw.get("bytes_sent", 0) or 0
        try:
            if int(bytes_out) > threshold_bytes:
                matched.append(e)
        except (ValueError, TypeError):
            continue
    return matched


def _sensitive_file_access(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect file access to sensitive directories."""
    sensitive_dirs = re.compile(
        r"(/etc/shadow|/etc/passwd|/etc/sudoers"
        r"|/root/|/var/log/auth"
        r"|C:\\Windows\\System32\\config"
        r"|\.ssh/|id_rsa|authorized_keys"
        r"|/etc/krb5\.keytab|SAM|NTDS\.dit"
        r"|\.aws/credentials|\.kube/config)",
        re.IGNORECASE,
    )
    return [
        e for e in events
        if e.get("log_source") in ("file_access", "security")
        and (
            sensitive_dirs.search(e.get("command_line", ""))
            or sensitive_dirs.search(e.get("description", ""))
            or sensitive_dirs.search(str(e.get("raw_data", {})))
        )
    ]


def _usb_device(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect USB device connection events."""
    return [
        e for e in events
        if (
            e.get("event_type", "").lower() in ("usb_connect", "usb_device",
                                                "device_connected")
            or "usb" in " ".join(e.get("tags", [])).lower()
            or "usb" in e.get("description", "").lower()
        )
    ]


def _unusual_dns(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect unusual DNS queries (high-entropy domains, TXT records, long labels)."""
    suspicious_tlds = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
                       ".onion", ".bit")
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") != "dns":
            continue
        raw = e.get("raw_data", {})
        query = raw.get("query", "") or raw.get("domain", "") or ""
        record_type = (raw.get("record_type", "") or raw.get("type", "")).upper()

        # TXT record queries can indicate C2 or exfiltration
        if record_type == "TXT":
            matched.append(e)
            continue

        # Long domain labels (possible DNS tunnelling)
        if any(len(part) > 40 for part in query.split(".")):
            matched.append(e)
            continue

        # Suspicious TLDs
        if any(query.lower().endswith(tld) for tld in suspicious_tlds):
            matched.append(e)
            continue
    return matched


def _web_shell(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect potential web shell activity."""
    webshell_patterns = re.compile(
        r"(cmd\.php|shell\.php|c99\.php|r57\.php|b374k"
        r"|eval\(|base64_decode\(|system\(|passthru\("
        r"|\.php\?cmd=|\.asp\?cmd=|\.jsp\?cmd="
        r"|webshell|web_shell"
        r"|whoami|ipconfig|ifconfig|uname\s+-a)",
        re.IGNORECASE,
    )
    return [
        e for e in events
        if e.get("log_source") in ("web_access", "process", "ids", "security")
        and (
            webshell_patterns.search(e.get("command_line", ""))
            or webshell_patterns.search(e.get("description", ""))
            or webshell_patterns.search(str(e.get("raw_data", {})))
        )
    ]


def _crontab_modification(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect crontab or scheduled-task modification."""
    cron_patterns = re.compile(
        r"(crontab\s+-[eirl]|/etc/cron|at\s+-f|atq|schtasks\s+/create"
        r"|schtasks\s+/change|Register-ScheduledTask"
        r"|New-ScheduledTask|systemctl\s+(enable|start)\s+.*\.timer)",
        re.IGNORECASE,
    )
    return [
        e for e in events
        if e.get("log_source") in ("process", "security", "application")
        and (
            cron_patterns.search(e.get("command_line", ""))
            or cron_patterns.search(e.get("description", ""))
        )
    ]


def _bulk_file_deletion(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect bulk file deletion (> 10 delete events in 60 seconds from same user)."""
    deletes = [
        e for e in events
        if e.get("log_source") in ("file_access", "security")
        and e.get("event_type", "").lower() in ("file_delete", "file_deletion",
                                                "delete", "removed")
    ]
    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in deletes:
        by_user.setdefault(e.get("user", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for user_events in by_user.values():
        for group in _events_in_window(user_events, 60):
            if len(group) > 10:
                matched.extend(group)
    return matched


# ---------------------------------------------------------------------------
# Additional rule condition functions
# ---------------------------------------------------------------------------

def _phishing_email(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect phishing email indicators: suspicious sender, attachment, failed SPF/DKIM."""
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") != "email":
            continue
        raw = e.get("raw_data", {})
        e.get("description", "").lower()
        # Check for suspicious indicators
        spf_fail = raw.get("SPF", "").lower() == "fail"
        dkim_fail = raw.get("DKIM", "").lower() == "fail"
        has_attachment = raw.get("HasAttachment", False)
        high_spam = (raw.get("SpamScore", 0) or 0) >= 5.0
        phishing_tag = "phishing" in " ".join(e.get("tags", [])).lower()

        if (spf_fail and dkim_fail) or (has_attachment and high_spam) or phishing_tag:
            matched.append(e)
    return matched


def _credential_dumping(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect credential dumping tools: mimikatz, procdump targeting lsass, secretsdump."""
    cred_patterns = re.compile(
        r"(mimikatz|sekurlsa|lsadump|procdump.*lsass|lsass\.dmp"
        r"|secretsdump|hashdump|credential.dump"
        r"|sam\.hive|system\.hive|security\.hive)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("process", "security"):
            continue
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        desc = e.get("description", "")
        if cred_patterns.search(cmd) or cred_patterns.search(proc) or cred_patterns.search(desc):
            matched.append(e)
    return matched


def _dcsync_attack(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect DCSync attack: directory replication requests from non-DC hosts."""
    dcsync_patterns = re.compile(
        r"(dcsync|DS-Replication|directory.replication|lsadump::dcsync"
        r"|MS-DRSR|DRSGetNCChanges|ntds\.dit)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        if dcsync_patterns.search(cmd) or dcsync_patterns.search(desc):
            matched.append(e)
    return matched


def _psexec_wmi_lateral(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect lateral movement via PsExec, WMI, or SMB admin shares."""
    lateral_patterns = re.compile(
        r"(psexec|PSEXESVC|wmiexec|wmiprvse|wmic.*process.*call"
        r"|ADMIN\$|IPC\$|C\$"
        r"|lateral.movement)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        if lateral_patterns.search(desc) or lateral_patterns.search(cmd) or lateral_patterns.search(proc):
            matched.append(e)
    return matched


def _cryptominer_detection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect cryptocurrency miner processes and mining pool connections."""
    miner_patterns = re.compile(
        r"(xmrig|xmr-stak|minerd|cpuminer|cgminer|bfgminer"
        r"|\.kworker.*stratum|stratum\+tcp|pool\.minexmr"
        r"|pool\.hashvault|nanopool|nicehash|coinhive"
        r"|cryptonight|monero.*mine|mining.*pool"
        r"|Resource.hijacking)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        desc = e.get("description", "")
        dst_host = e.get("dst_host", "")
        if (miner_patterns.search(cmd) or miner_patterns.search(proc)
                or miner_patterns.search(desc) or miner_patterns.search(dst_host)):
            matched.append(e)
    return matched


def _database_dump(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect database dump commands (pg_dump, mysqldump, pg_dumpall, etc.)."""
    dump_patterns = re.compile(
        r"(pg_dump|pg_dumpall|mysqldump|mongodump|sqlcmd.*-Q"
        r"|bcp.*out|sqlite3.*\.dump|db_backup)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        desc = e.get("description", "")
        if dump_patterns.search(cmd) or dump_patterns.search(proc) or dump_patterns.search(desc):
            matched.append(e)
    return matched


def _archive_creation(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect data archiving with password protection or encryption flags."""
    archive_patterns = re.compile(
        r"(7z\.exe\s+a|7z\s+a|rar\s+a|zip\s+.*-e|zip\s+.*-P"
        r"|tar\s+.*-cz|Data.compressed|archive.*password"
        r"|7z\.exe|\.7z|\.rar)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("process", "security", "file_access"):
            continue
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        desc = e.get("description", "")
        if archive_patterns.search(cmd) or archive_patterns.search(proc) or archive_patterns.search(desc):
            matched.append(e)
    return matched


def _cloud_exfiltration(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect data upload to personal cloud storage or personal email services."""
    cloud_patterns = re.compile(
        r"(drive\.google\.com|mega\.nz|dropbox\.com|wetransfer\.com"
        r"|onedrive\.live\.com|box\.com/upload"
        r"|protonmail|tutanota|guerrillamail"
        r"|personal.*cloud|personal.*email"
        r"|graph\.microsoft\.com.*upload)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        raw = e.get("raw_data", {})
        url = raw.get("URL", "") or raw.get("url", "")
        dst_host = e.get("dst_host", "")

        if (cloud_patterns.search(desc) or cloud_patterns.search(url)
                or cloud_patterns.search(dst_host)):
            matched.append(e)
    return matched


def _off_hours_file_access(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect file access outside business hours (before 8:00 or after 18:00)."""
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("file_access", "security"):
            continue
        if not e.get("is_malicious", False):
            continue
        ts = _parse_ts(e.get("timestamp", ""))
        if ts.hour < 8 or ts.hour >= 18:
            matched.append(e)
    return matched


def _bulk_file_access(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect bulk file read/copy operations (>5 file accesses by same user in 60s)."""
    reads = [
        e for e in events
        if e.get("log_source") == "file_access"
        and e.get("event_type", "").lower() in ("file_read", "file_write", "file_create", "file_rename")
    ]
    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in reads:
        by_user.setdefault(e.get("user", "unknown"), []).append(e)

    matched: list[dict[str, Any]] = []
    for user_events in by_user.values():
        for group in _events_in_window(user_events, 60):
            if len(group) > 5:
                matched.extend(group)
    return matched


def _log_tampering(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect event log clearing or tampering with security logs."""
    tamper_patterns = re.compile(
        r"(wevtutil\s+cl|Clear-EventLog|\.evtx|Audit.log.Cleared"
        r"|Log.cleared|Event.Log.cleared|1102.*Audit"
        r"|sdelete|cipher\s+/w|secure.*wip"
        r"|clear.*history|ClearMyTracks)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        proc = e.get("process_name", "")
        if (tamper_patterns.search(cmd) or tamper_patterns.search(desc)
                or tamper_patterns.search(proc)):
            matched.append(e)
    return matched


def _supply_chain_attack(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect supply chain compromise: package managers spawning shells or downloading payloads."""
    sc_patterns = re.compile(
        r"(npm.*exec|pip.*install.*-e|node\s+-e.*child_process"
        r"|python.*setup\.py.*install|bash\s+-i.*dev/tcp"
        r"|Suspicious.*Node|Suspicious.*npm"
        r"|trojanized|supply.chain)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("process", "security"):
            continue
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        if sc_patterns.search(cmd) or sc_patterns.search(desc):
            matched.append(e)
    return matched


def _discovery_enumeration(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Active Directory enumeration and reconnaissance tools."""
    enum_patterns = re.compile(
        r"(adfind|sharphound|bloodhound|rubeus|ldapsearch"
        r"|nltest.*dclist|nltest.*domain_trusts"
        r"|net\s+group.*domain|net\s+user.*domain"
        r"|net\s+view|Get-AD|dsquery|csvde|ldifde"
        r"|Discovery:)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("process", "security"):
            continue
        cmd = e.get("command_line", "")
        proc = e.get("process_name", "")
        desc = e.get("description", "")
        if (enum_patterns.search(cmd) or enum_patterns.search(proc)
                or enum_patterns.search(desc)):
            matched.append(e)
    return matched


def _exploit_privesc(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect privilege escalation via known exploit patterns (PwnKit, etc.)."""
    exploit_patterns = re.compile(
        r"(CVE-\d{4}-\d+|pwnkit|pkexec.*exploit|exploit.*priv"
        r"|UID.change.*root|escalat.*root"
        r"|gcc.*tmp.*\.c|/tmp/\.[a-z]+\s)"
        r"|(Privilege.escalation.exploit)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        tags = " ".join(e.get("tags", []))
        if (exploit_patterns.search(cmd) or exploit_patterns.search(desc)
                or "privilege_escalation" in tags or "exploit" in tags):
            matched.append(e)
    return matched


def _credential_harvesting(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect credential harvesting via phishing or OAuth abuse."""
    harvest_patterns = re.compile(
        r"(credential.harvest|fake.*portal|OAuth.*consent.*external"
        r"|Suspicious.*OAuth|phishing.*credential"
        r"|submitted.credentials|login-microsoftonline"
        r"|micros0ft-update)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        raw = e.get("raw_data", {})
        url = raw.get("URL", "") or raw.get("url", "")
        if harvest_patterns.search(desc) or harvest_patterns.search(url):
            matched.append(e)
    return matched


def _cobalt_strike_beacon(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Cobalt Strike beacon or C2 beacon activity."""
    beacon_patterns = re.compile(
        r"(cobalt.strike|beacon|C2.*beacon|c2_traffic"
        r"|malleable.*c2|NativeZone|rundll32.*DLL"
        r"|rundll32.*dll|HTTPS.*beacon"
        r"|Cobalt.*Strike.*beacon)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        proc = e.get("process_name", "")
        tags = " ".join(e.get("tags", []))
        if (beacon_patterns.search(cmd) or beacon_patterns.search(desc)
                or beacon_patterns.search(proc) or "c2_traffic" in tags):
            matched.append(e)
    return matched


def _data_staging(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect data staging: sensitive files copied to staging directories."""
    staging_patterns = re.compile(
        r"(Sensitive.file|sensitive.*access|staging|stage"
        r"|employee.*salaries|personal.*data|strategic.*plan"
        r"|board.*meeting|confidential|payroll"
        r"|mergers|patents|quarterly.*report)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("file_access",):
            continue
        desc = e.get("description", "")
        raw = e.get("raw_data", {})
        filepath = raw.get("TargetFilename", "")
        if staging_patterns.search(desc) or staging_patterns.search(filepath):
            matched.append(e)
    return matched


def _robocopy_bulk_copy(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect bulk file copy operations using robocopy, xcopy, or similar tools."""
    copy_patterns = re.compile(
        r"(robocopy|xcopy|copy.*\/(e|s|mir)|bulk.*copy"
        r"|/MIR\s|/COPY:)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") not in ("process", "security"):
            continue
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        if copy_patterns.search(cmd) or copy_patterns.search(desc):
            matched.append(e)
    return matched


def _kerberoasting(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Kerberoasting: TGS ticket requests with RC4 encryption (0x17) or Rubeus/GetUserSPNs."""
    kerberoast_re = re.compile(
        r"(kerberoast|GetUserSPNs|Rubeus.*kerberoast"
        r"|0x17.*RC4|RC4.*kerberos"
        r"|SPN.*ticket|ServicePrincipalName.*request"
        r"|T1558\.003)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        tags = " ".join(e.get("tags", []))
        if (kerberoast_re.search(desc) or kerberoast_re.search(cmd)
                or "kerberoasting" in tags or "T1558.003" in tags):
            matched.append(e)
    return matched


def _pass_the_hash(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Pass-the-Hash attacks: NTLM auth from non-standard hosts, sekurlsa::pth."""
    pth_re = re.compile(
        r"(sekurlsa::pth|Pass.the.Hash|pass.the.hash"
        r"|pth.*\/ntlm|ntlm.*hash.*logon"
        r"|overpass.the.hash|T1550\.002"
        r"|NTHash.*logon|wce\.exe.*\-s|mimikatz.*pth)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        if pth_re.search(desc) or pth_re.search(cmd):
            matched.append(e)
    return matched


def _process_injection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect process injection: hollowing, reflective DLL, APC injection."""
    injection_re = re.compile(
        r"(process.hollow|reflective.*dll|dll.inject"
        r"|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread"
        r"|NtMapViewOfSection|QueueUserAPC|NtCreateThreadEx"
        r"|shellcode.inject|mavinject|T1055"
        r"|inject.*memory|memory.*inject)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        tags = " ".join(e.get("tags", []))
        if (injection_re.search(desc) or injection_re.search(cmd)
                or "process_injection" in tags):
            matched.append(e)
    return matched


def _lolbas_execution(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Living off the Land Binaries (LOLBAS) abuse for execution/download."""
    lolbas_re = re.compile(
        r"(mshta\.exe.*http|regsvr32.*scrobj"
        r"|certutil.*-decode|certutil.*urlcache"
        r"|bitsadmin.*\/transfer|wscript.*http"
        r"|cscript.*http|rundll32.*javascript"
        r"|msiexec.*\/q.*http|forfiles.*\/p.*\/m"
        r"|ieexec\.exe|msbuild\.exe.*tasks"
        r"|installutil\.exe|odbcconf.*REGSVR"
        r"|regasm|regsvcs|cmstp|msconfig.*autorun"
        r"|wmic.*process.*create.*http)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("event_type") not in ("process", "security"):
            continue
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        if lolbas_re.search(cmd) or lolbas_re.search(desc):
            matched.append(e)
    return matched


def _dga_detection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect DGA (Domain Generation Algorithm) by identifying high-entropy domain labels."""
    import math

    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    suspicious_tlds = {".xyz", ".top", ".club", ".online", ".site", ".info",
                       ".biz", ".tk", ".pw", ".cc", ".io", ".to", ".ru"}
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("event_type") not in ("dns",):
            continue
        domain: str = e.get("domain", "") or ""
        if not domain or "." not in domain:
            continue
        labels = domain.split(".")
        longest_label = max(labels[:-1], key=len, default="")
        tld = "." + labels[-1] if labels else ""
        entropy = _shannon_entropy(longest_label)
        is_suspicious = (
            (entropy > 3.5 and len(longest_label) > 12)
            or tld in suspicious_tlds
            or len(domain) > 52
        )
        if is_suspicious:
            matched.append(e)
    return matched


def _dns_tunneling_entropy(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect DNS tunneling via long/high-entropy subdomains used as data channels."""
    import math

    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("event_type") not in ("dns",):
            continue
        domain: str = e.get("domain", "") or ""
        if not domain or "." not in domain:
            continue
        subdomain = ".".join(domain.split(".")[:-2]) if len(domain.split(".")) > 2 else ""
        if not subdomain:
            continue
        entropy = _shannon_entropy(subdomain.replace(".", ""))
        query_type = e.get("query_type", "")
        if (len(subdomain) > 40 and entropy > 3.2) or (query_type in ("TXT", "NULL", "CNAME") and entropy > 3.0):
            matched.append(e)
    return matched


def _as_rep_roasting(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect AS-REP Roasting: Kerberos AS requests without pre-authentication."""
    asrep_re = re.compile(
        r"(AS-REP.roast|asreproast|GetNPUsers"
        r"|DoesNotRequirePreAuth|DONT_REQ_PREAUTH"
        r"|asrep.*hash|T1558\.004"
        r"|Rubeus.*asreproast|kerberospreauth.*disabled)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        if asrep_re.search(desc) or asrep_re.search(cmd):
            matched.append(e)
    return matched


def _container_escape(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect container escape attempts: nsenter, privileged container abuse, Docker socket."""
    escape_re = re.compile(
        r"(nsenter.*--target.*1|nsenter.*--pid.*host"
        r"|docker.*--privileged|mount.*\/dev\/sda"
        r"|chroot.*\/mnt|cgroup.*release_agent"
        r"|docker\.sock.*curl|kubectl.*exec.*nsenter"
        r"|T1611|container.*escape|escape.*container"
        r"|deepce|cdk.*exploit)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        tags = " ".join(e.get("tags", []))
        if escape_re.search(desc) or escape_re.search(cmd) or "container_escape" in tags:
            matched.append(e)
    return matched


def _cloud_imds_abuse(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect abuse of cloud instance metadata service (IMDS) for credential theft."""
    imds_re = re.compile(
        r"(169\.254\.169\.254"
        r"|metadata\.google\.internal"
        r"|metadata\.azure\.com"
        r"|imds\/latest\/meta-data"
        r"|iam\/security-credentials"
        r"|T1552\.005"
        r"|instance.metadata.*credential)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        url = e.get("url", "")
        cmd = e.get("command_line", "")
        if imds_re.search(desc) or imds_re.search(url) or imds_re.search(cmd):
            matched.append(e)
    return matched


def _ransomware_indicators(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect ransomware activity: mass file extension changes, ransom note drops, encryption."""
    ransomware_re = re.compile(
        r"(ransom.*note|RECOVER.*FILES|README.*DECRYPT"
        r"|\.locked$|\.encrypt|\.blackcat|\.crypt"
        r"|vssadmin.*delete.*shadows"
        r"|wbadmin.*delete.*catalog"
        r"|bcdedit.*recoveryenabled.*No"
        r"|net.*stop.*veeam|net.*stop.*MSSQL"
        r"|Set-MpPreference.*DisableRealtime"
        r"|T1486|data.*encrypted.*impact)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        tags = " ".join(e.get("tags", []))
        if ransomware_re.search(desc) or ransomware_re.search(cmd) or "ransomware" in tags:
            matched.append(e)
    return matched


def _shadow_copy_deletion(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Volume Shadow Copy deletion — strong ransomware/wiper indicator."""
    vss_re = re.compile(
        r"(vssadmin.*delete|wmic.*shadowcopy.*delete"
        r"|shadow.*copy.*delet|Delete.*ShadowCopy"
        r"|WMIC.*delete.*shadow|T1490"
        r"|Inhibit.*System.*Recovery)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        if vss_re.search(desc) or vss_re.search(cmd):
            matched.append(e)
    return matched


def _golden_ticket(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect Golden Ticket and Silver Ticket Kerberos forgery."""
    golden_re = re.compile(
        r"(golden.*ticket|silver.*ticket"
        r"|kerberos::golden|kerberos::silver"
        r"|kerberos::ptt.*kirbi"
        r"|krbtgt.*hash.*forge"
        r"|T1558\.001|T1558\.002"
        r"|Mimikatz.*kerberos.*golden)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        desc = e.get("description", "")
        cmd = e.get("command_line", "")
        if golden_re.search(desc) or golden_re.search(cmd):
            matched.append(e)
    return matched


def _account_creation(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect new account creation, especially domain admin accounts."""
    account_patterns = re.compile(
        r"(net\s+user.*\/add|New-ADUser|dsadd\s+user"
        r"|account.*created|Account.Created"
        r"|domain.admin.*add|Domain.Admins.*add"
        r"|net\s+group.*Domain.*Admins.*\/add)",
        re.IGNORECASE,
    )
    matched: list[dict[str, Any]] = []
    for e in events:
        cmd = e.get("command_line", "")
        desc = e.get("description", "")
        tags = " ".join(e.get("tags", []))
        if (account_patterns.search(cmd) or account_patterns.search(desc)
                or "account_creation" in tags):
            matched.append(e)
    return matched


# ---------------------------------------------------------------------------
# Pre-built rule catalogue
# ---------------------------------------------------------------------------

DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="RULE-001",
        name="Multiple Failed Login Attempts",
        description="More than 5 failed login attempts from the same user within 5 minutes.",
        severity="high",
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        condition=_multiple_failed_logins,
        threshold=5,
        time_window_seconds=300,
    ),
    DetectionRule(
        rule_id="RULE-002",
        name="Successful Login After Multiple Failures",
        description="A successful login following 3 or more consecutive failures for the same user.",
        severity="high",
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        condition=_login_after_failures,
        threshold=3,
    ),
    DetectionRule(
        rule_id="RULE-003",
        name="Login From External IP",
        description="Successful authentication originating from a non-RFC-1918 IP address.",
        severity="medium",
        tactic="Initial Access",
        technique_id="T1078",
        technique_name="Valid Accounts",
        condition=_login_external_ip,
    ),
    DetectionRule(
        rule_id="RULE-004",
        name="Off-Hours Login",
        description="Successful login detected outside normal business hours (before 06:00 or after 22:00).",
        severity="medium",
        tactic="Initial Access",
        technique_id="T1078",
        technique_name="Valid Accounts",
        condition=_off_hours_login,
    ),
    DetectionRule(
        rule_id="RULE-005",
        name="Port Scan Detected",
        description="More than 10 distinct destination ports contacted from the same source within 60 seconds.",
        severity="high",
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        condition=_port_scan,
        threshold=10,
        time_window_seconds=60,
    ),
    DetectionRule(
        rule_id="RULE-006",
        name="SSH Brute Force",
        description="More than 20 SSH authentication failures from the same source in 10 minutes.",
        severity="critical",
        tactic="Credential Access",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        condition=_ssh_brute_force,
        threshold=20,
        time_window_seconds=600,
    ),
    DetectionRule(
        rule_id="RULE-007",
        name="Privilege Escalation Command",
        description="Execution of privilege escalation utilities (sudo, su, runas, pkexec).",
        severity="medium",
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        condition=_privilege_escalation,
    ),
    DetectionRule(
        rule_id="RULE-008",
        name="Suspicious Process Execution",
        description="Reverse shell, encoded command, or living-off-the-land binary execution detected.",
        severity="critical",
        tactic="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        condition=_suspicious_process,
    ),
    DetectionRule(
        rule_id="RULE-009",
        name="Large Outbound Data Transfer",
        description="Single outbound network flow exceeding 100 MB, possible data exfiltration.",
        severity="high",
        tactic="Exfiltration",
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        condition=_large_outbound_transfer,
        threshold=104857600,
    ),
    DetectionRule(
        rule_id="RULE-010",
        name="Sensitive File Access",
        description="Access to sensitive system files (shadow, SAM, SSH keys, credentials).",
        severity="high",
        tactic="Credential Access",
        technique_id="T1552",
        technique_name="Unsecured Credentials",
        condition=_sensitive_file_access,
    ),
    DetectionRule(
        rule_id="RULE-011",
        name="USB Device Connection",
        description="A USB storage device was connected to a monitored host.",
        severity="low",
        tactic="Initial Access",
        technique_id="T1091",
        technique_name="Replication Through Removable Media",
        condition=_usb_device,
    ),
    DetectionRule(
        rule_id="RULE-012",
        name="Unusual DNS Query",
        description="DNS query with suspicious TLD, long label, or TXT record type indicating possible tunnelling or C2.",
        severity="medium",
        tactic="Command and Control",
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        condition=_unusual_dns,
    ),
    DetectionRule(
        rule_id="RULE-013",
        name="Web Shell Detected",
        description="Indicators of web shell upload or execution observed in web-access or process logs.",
        severity="critical",
        tactic="Persistence",
        technique_id="T1505.003",
        technique_name="Server Software Component: Web Shell",
        condition=_web_shell,
    ),
    DetectionRule(
        rule_id="RULE-014",
        name="Scheduled Task / Crontab Modification",
        description="Creation or modification of crontab entries or Windows scheduled tasks.",
        severity="medium",
        tactic="Persistence",
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        condition=_crontab_modification,
    ),
    DetectionRule(
        rule_id="RULE-015",
        name="Bulk File Deletion",
        description="More than 10 file deletion events from the same user within 60 seconds.",
        severity="high",
        tactic="Impact",
        technique_id="T1485",
        technique_name="Data Destruction",
        condition=_bulk_file_deletion,
        threshold=10,
        time_window_seconds=60,
    ),

    # --- NEW RULES for improved detection coverage ---

    DetectionRule(
        rule_id="RULE-016",
        name="Phishing Email Detected",
        description="Inbound email with suspicious indicators: failed SPF/DKIM, high spam score, or phishing attachment.",
        severity="high",
        tactic="Initial Access",
        technique_id="T1566",
        technique_name="Phishing",
        condition=_phishing_email,
    ),
    DetectionRule(
        rule_id="RULE-017",
        name="Credential Dumping Detected",
        description="Credential dumping tool execution detected (Mimikatz, procdump targeting LSASS, secretsdump).",
        severity="critical",
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        condition=_credential_dumping,
    ),
    DetectionRule(
        rule_id="RULE-018",
        name="DCSync Attack Detected",
        description="Directory replication request from non-domain controller, indicating DCSync credential theft.",
        severity="critical",
        tactic="Credential Access",
        technique_id="T1003.006",
        technique_name="OS Credential Dumping: DCSync",
        condition=_dcsync_attack,
    ),
    DetectionRule(
        rule_id="RULE-019",
        name="PsExec / WMI Lateral Movement",
        description="Lateral movement via PsExec service, WMI execution, or admin share access detected.",
        severity="high",
        tactic="Lateral Movement",
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        condition=_psexec_wmi_lateral,
    ),
    DetectionRule(
        rule_id="RULE-020",
        name="Cryptocurrency Miner Detected",
        description="Cryptocurrency miner process or mining pool connection detected (XMRig, Stratum protocol).",
        severity="high",
        tactic="Impact",
        technique_id="T1496",
        technique_name="Resource Hijacking",
        condition=_cryptominer_detection,
    ),
    DetectionRule(
        rule_id="RULE-021",
        name="Database Dump Detected",
        description="Database dump command execution detected (pg_dump, mysqldump, pg_dumpall).",
        severity="high",
        tactic="Collection",
        technique_id="T1005",
        technique_name="Data from Local System",
        condition=_database_dump,
    ),
    DetectionRule(
        rule_id="RULE-022",
        name="Data Archive Creation",
        description="Data archiving with compression or encryption detected (7-Zip, RAR, encrypted archives).",
        severity="medium",
        tactic="Collection",
        technique_id="T1560.001",
        technique_name="Archive Collected Data: Archive via Utility",
        condition=_archive_creation,
    ),
    DetectionRule(
        rule_id="RULE-023",
        name="Cloud Storage Exfiltration",
        description="Data upload to personal cloud storage or email service detected (Google Drive, Mega, ProtonMail).",
        severity="high",
        tactic="Exfiltration",
        technique_id="T1567.002",
        technique_name="Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        condition=_cloud_exfiltration,
    ),
    DetectionRule(
        rule_id="RULE-024",
        name="Off-Hours File Access",
        description="Suspicious file access activity detected outside normal business hours (before 08:00 or after 18:00).",
        severity="medium",
        tactic="Collection",
        technique_id="T1005",
        technique_name="Data from Local System",
        condition=_off_hours_file_access,
    ),
    DetectionRule(
        rule_id="RULE-025",
        name="Bulk File Access",
        description="More than 5 file read/copy operations from the same user within 60 seconds.",
        severity="medium",
        tactic="Collection",
        technique_id="T1074.001",
        technique_name="Data Staged: Local Data Staging",
        condition=_bulk_file_access,
        threshold=5,
        time_window_seconds=60,
    ),
    DetectionRule(
        rule_id="RULE-026",
        name="Log Tampering / Anti-Forensics",
        description="Event log clearing, secure wiping, or anti-forensics tool usage detected.",
        severity="critical",
        tactic="Defense Evasion",
        technique_id="T1070.004",
        technique_name="Indicator Removal: File Deletion",
        condition=_log_tampering,
    ),
    DetectionRule(
        rule_id="RULE-027",
        name="Supply Chain Compromise",
        description="Package manager spawning shell or downloading suspicious payload detected.",
        severity="critical",
        tactic="Initial Access",
        technique_id="T1195.002",
        technique_name="Supply Chain Compromise: Compromise Software Supply Chain",
        condition=_supply_chain_attack,
    ),
    DetectionRule(
        rule_id="RULE-028",
        name="Active Directory Enumeration",
        description="AD reconnaissance tools detected: ADFind, SharpHound, BloodHound, Rubeus, nltest.",
        severity="high",
        tactic="Discovery",
        technique_id="T1087.002",
        technique_name="Account Discovery: Domain Account",
        condition=_discovery_enumeration,
    ),
    DetectionRule(
        rule_id="RULE-029",
        name="Privilege Escalation Exploit",
        description="Known privilege escalation exploit pattern detected (PwnKit, kernel exploit, UID change to root).",
        severity="critical",
        tactic="Privilege Escalation",
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        condition=_exploit_privesc,
    ),
    DetectionRule(
        rule_id="RULE-030",
        name="Credential Harvesting via Phishing",
        description="Credential harvesting through fake login portal or OAuth abuse detected.",
        severity="high",
        tactic="Credential Access",
        technique_id="T1556",
        technique_name="Modify Authentication Process",
        condition=_credential_harvesting,
    ),
    DetectionRule(
        rule_id="RULE-031",
        name="Cobalt Strike Beacon Activity",
        description="Cobalt Strike beacon or C2 implant activity detected (DLL sideloading, beacon traffic).",
        severity="critical",
        tactic="Command and Control",
        technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        condition=_cobalt_strike_beacon,
    ),
    DetectionRule(
        rule_id="RULE-032",
        name="Sensitive Data Staging",
        description="Access to sensitive files (salaries, PII, strategic documents) indicating data staging for exfiltration.",
        severity="high",
        tactic="Collection",
        technique_id="T1005",
        technique_name="Data from Local System",
        condition=_data_staging,
    ),
    DetectionRule(
        rule_id="RULE-033",
        name="Bulk File Copy Tool",
        description="Bulk file copy tool usage detected (robocopy, xcopy with recursive flags).",
        severity="medium",
        tactic="Collection",
        technique_id="T1074.001",
        technique_name="Data Staged: Local Data Staging",
        condition=_robocopy_bulk_copy,
    ),
    DetectionRule(
        rule_id="RULE-034",
        name="Suspicious Account Creation",
        description="New user account created, potentially for persistence or backdoor access.",
        severity="high",
        tactic="Persistence",
        technique_id="T1136",
        technique_name="Create Account",
        condition=_account_creation,
    ),

    # --- ENTERPRISE RULES (RULE-035 to RULE-046) ---

    DetectionRule(
        rule_id="RULE-035",
        name="Kerberoasting Attack Detected",
        description="TGS ticket requests with RC4 encryption or Rubeus/GetUserSPNs tooling detected — Kerberoasting in progress.",
        severity="critical",
        tactic="Credential Access",
        technique_id="T1558.003",
        technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
        condition=_kerberoasting,
    ),
    DetectionRule(
        rule_id="RULE-036",
        name="Pass-the-Hash Attack Detected",
        description="NTLM hash used directly for authentication without knowing the plaintext password (Pass-the-Hash / Overpass-the-Hash).",
        severity="critical",
        tactic="Lateral Movement",
        technique_id="T1550.002",
        technique_name="Use Alternate Authentication Material: Pass the Hash",
        condition=_pass_the_hash,
    ),
    DetectionRule(
        rule_id="RULE-037",
        name="Process Injection Detected",
        description="Process hollowing, reflective DLL injection, or APC queue injection techniques detected via memory operation APIs.",
        severity="critical",
        tactic="Defense Evasion",
        technique_id="T1055",
        technique_name="Process Injection",
        condition=_process_injection,
    ),
    DetectionRule(
        rule_id="RULE-038",
        name="LOLBAS Execution (Living off the Land)",
        description="Abuse of legitimate Windows binaries (mshta, certutil, regsvr32, bitsadmin, etc.) for malicious code execution or download.",
        severity="high",
        tactic="Execution",
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
        condition=_lolbas_execution,
    ),
    DetectionRule(
        rule_id="RULE-039",
        name="DGA Domain Activity Detected",
        description="High-entropy domain labels or suspicious TLDs indicate Domain Generation Algorithm (DGA) malware communication.",
        severity="high",
        tactic="Command and Control",
        technique_id="T1568.002",
        technique_name="Dynamic Resolution: Domain Generation Algorithms",
        condition=_dga_detection,
    ),
    DetectionRule(
        rule_id="RULE-040",
        name="DNS Tunneling Detected",
        description="Long high-entropy subdomain labels or TXT/NULL DNS record abuse indicate DNS tunneling for C2 data exfiltration.",
        severity="critical",
        tactic="Command and Control",
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        condition=_dns_tunneling_entropy,
    ),
    DetectionRule(
        rule_id="RULE-041",
        name="AS-REP Roasting Detected",
        description="Kerberos AS-REQ requests for accounts with pre-authentication disabled — offline hash cracking attempt.",
        severity="high",
        tactic="Credential Access",
        technique_id="T1558.004",
        technique_name="Steal or Forge Kerberos Tickets: AS-REP Roasting",
        condition=_as_rep_roasting,
    ),
    DetectionRule(
        rule_id="RULE-042",
        name="Container Escape Attempt",
        description="nsenter targeting host PID 1, privileged container abuse, or Docker socket exploitation detected.",
        severity="critical",
        tactic="Privilege Escalation",
        technique_id="T1611",
        technique_name="Escape to Host",
        condition=_container_escape,
    ),
    DetectionRule(
        rule_id="RULE-043",
        name="Cloud IMDS Credential Theft",
        description="Access to AWS/Azure/GCP instance metadata service endpoint to steal IAM role credentials.",
        severity="critical",
        tactic="Credential Access",
        technique_id="T1552.005",
        technique_name="Unsecured Credentials: Cloud Instance Metadata API",
        condition=_cloud_imds_abuse,
    ),
    DetectionRule(
        rule_id="RULE-044",
        name="Ransomware Activity Detected",
        description="Ransom note creation, mass file encryption, backup service termination, or defender disabling — strong ransomware indicators.",
        severity="critical",
        tactic="Impact",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        condition=_ransomware_indicators,
    ),
    DetectionRule(
        rule_id="RULE-045",
        name="Volume Shadow Copy Deletion",
        description="vssadmin/wmic delete shadows command detected — ransomware or wiper attempting to prevent recovery.",
        severity="critical",
        tactic="Impact",
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
        condition=_shadow_copy_deletion,
    ),
    DetectionRule(
        rule_id="RULE-046",
        name="Golden / Silver Ticket Forging",
        description="Mimikatz kerberos::golden or kerberos::silver command detected — complete domain compromise via forged Kerberos tickets.",
        severity="critical",
        tactic="Privilege Escalation",
        technique_id="T1558.001",
        technique_name="Steal or Forge Kerberos Tickets: Golden Ticket",
        condition=_golden_ticket,
    ),
]
