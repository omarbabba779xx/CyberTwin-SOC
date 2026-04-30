"""Rule condition functions.

Each function receives a list of normalised log-event dicts and returns
the subset of events that matched the rule's logic. They are used by the
:class:`DetectionRule` instances declared in ``catalogue.py``.
"""

from __future__ import annotations

import math
import re
from typing import Any

from .helpers import _events_in_window, _is_external_ip, _parse_ts


# ---------------------------------------------------------------------------
# Authentication / Brute force
# ---------------------------------------------------------------------------

def _multiple_failed_logins(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect > 5 failed login events from the same user within 5 minutes."""
    failed = [
        e for e in events
        if e.get("log_source") == "authentication"
        and e.get("event_type", "").lower() in ("login_failure", "failed_login",
                                                "authentication_failure", "logon_failure")
    ]
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


# ---------------------------------------------------------------------------
# Network / Discovery / DNS
# ---------------------------------------------------------------------------

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

        if record_type == "TXT":
            matched.append(e)
            continue

        if any(len(part) > 40 for part in query.split(".")):
            matched.append(e)
            continue

        if any(query.lower().endswith(tld) for tld in suspicious_tlds):
            matched.append(e)
            continue
    return matched


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _dga_detection(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect DGA (Domain Generation Algorithm) by identifying high-entropy domain labels."""
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


# ---------------------------------------------------------------------------
# Process / Execution / Privilege escalation
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Credential access (dumping / forging / harvesting)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Files / Collection / Staging
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

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
# Defense evasion
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Email / Initial access
# ---------------------------------------------------------------------------

def _phishing_email(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect phishing email indicators: suspicious sender, attachment, failed SPF/DKIM."""
    matched: list[dict[str, Any]] = []
    for e in events:
        if e.get("log_source") != "email":
            continue
        raw = e.get("raw_data", {})
        e.get("description", "").lower()
        spf_fail = raw.get("SPF", "").lower() == "fail"
        dkim_fail = raw.get("DKIM", "").lower() == "fail"
        has_attachment = raw.get("HasAttachment", False)
        high_spam = (raw.get("SpamScore", 0) or 0) >= 5.0
        phishing_tag = "phishing" in " ".join(e.get("tags", [])).lower()

        if (spf_fail and dkim_fail) or (has_attachment and high_spam) or phishing_tag:
            matched.append(e)
    return matched


# ---------------------------------------------------------------------------
# Command and Control
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Cloud / Container
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Impact
# ---------------------------------------------------------------------------

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
