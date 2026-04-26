"""
Normal (benign) activity generator for the CyberTwin SOC simulation.

Produces realistic event streams that mirror everyday corporate network
usage: logins, logouts, file access, web browsing, email, application
use, and DNS queries.  Activity respects each user's configured work
hours and access rights.
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .environment import EnvironmentBuilder


# ---------------------------------------------------------------------------
# Lookup tables for realistic content generation
# ---------------------------------------------------------------------------

_WEB_DOMAINS = [
    "google.com", "stackoverflow.com", "github.com", "linkedin.com",
    "wikipedia.org", "docs.microsoft.com", "medium.com", "slack.com",
    "outlook.office365.com", "teams.microsoft.com", "notion.so",
    "confluence.internal", "jira.internal", "drive.google.com",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
]

_FILE_PATHS = {
    "Human Resources": [
        "\\\\srv-db-01\\hr\\employee_records.xlsx",
        "\\\\srv-db-01\\hr\\onboarding_checklist.docx",
        "\\\\srv-db-01\\hr\\leave_requests_2024.csv",
        "\\\\srv-db-01\\shared\\company_policies.pdf",
    ],
    "Engineering": [
        "/home/jean.martin/projects/api-service/main.py",
        "/home/jean.martin/projects/frontend/src/App.tsx",
        "\\\\srv-db-01\\shared\\architecture_diagram.pdf",
        "\\\\srv-db-01\\engineering\\deployment_runbook.md",
    ],
    "Finance": [
        "\\\\srv-db-01\\finance\\quarterly_report_Q4.xlsx",
        "\\\\srv-db-01\\finance\\budget_forecast_2025.xlsx",
        "\\\\srv-db-01\\finance\\invoices\\invoice_2024_0312.pdf",
        "\\\\srv-db-01\\shared\\company_policies.pdf",
    ],
    "IT": [
        "/var/log/syslog",
        "/etc/nginx/nginx.conf",
        "\\\\srv-ad-01\\config\\group_policy.xml",
        "\\\\srv-db-01\\backups\\db_backup_manifest.json",
    ],
}

_APPLICATIONS = {
    "Human Resources": ["Outlook", "Word", "Excel", "Chrome", "HR Portal"],
    "Engineering": ["VS Code", "Terminal", "Docker Desktop", "Firefox", "Postman"],
    "Finance": ["Outlook", "Excel", "SAP ERP Client", "Chrome", "Power BI"],
    "IT": ["Terminal", "PuTTY", "Wireshark", "Chrome", "PowerShell"],
}

_EMAIL_SUBJECTS_INTERNAL = [
    "Re: Weekly sync agenda",
    "Updated project timeline",
    "Meeting notes - {date}",
    "Quick question about the report",
    "FYI: Policy update",
    "Action required: review document",
    "Team lunch this Friday?",
    "Re: Budget approval",
    "Deployment schedule change",
    "New hire orientation details",
]

_EMAIL_SUBJECTS_EXTERNAL = [
    "Invoice #{num}",
    "Partnership proposal",
    "Newsletter - {date}",
    "Subscription renewal notice",
    "Webinar invitation",
    "Vendor quote request",
    "Conference registration confirmation",
]

_DNS_INTERNAL = [
    "srv-ad-01.cybertwin.local",
    "srv-db-01.cybertwin.local",
    "srv-web-01.cybertwin.local",
    "srv-mail-01.cybertwin.local",
    "intranet.cybertwin.local",
    "mail.cybertwin.local",
    "erp.cybertwin.local",
    "git.cybertwin.local",
    "ci.cybertwin.local",
]

_DB_QUERIES_NORMAL = [
    "SELECT id, name, email FROM employees WHERE department = '{dept}'",
    "SELECT COUNT(*) FROM sessions WHERE active = true",
    "SELECT * FROM products WHERE category = 'hardware' LIMIT 50",
    "SELECT invoice_id, amount, due_date FROM invoices WHERE status = 'pending'",
    "SELECT username, last_login FROM users WHERE last_login > NOW() - INTERVAL '7 days'",
    "INSERT INTO audit_log (user_id, action, timestamp) VALUES ('{user}', 'view_report', NOW())",
    "UPDATE user_preferences SET theme = 'dark' WHERE user_id = '{user}'",
    "SELECT p.name, p.price FROM products p JOIN orders o ON p.id = o.product_id WHERE o.date > '2024-01-01'",
]

_DB_TABLES_NORMAL = [
    "employees", "sessions", "products", "invoices", "audit_log",
    "user_preferences", "departments", "leave_requests", "timesheets",
]

_FIREWALL_RULES_NORMAL = [
    "Allow-HTTP-Outbound", "Allow-HTTPS-Outbound", "Allow-DNS",
    "Allow-SMTP-Internal", "Allow-LDAP-Internal", "Allow-Kerberos",
    "Allow-SSH-ServerDMZ", "Allow-RDP-Internal", "Allow-NTP",
    "Allow-ICMP-Internal",
]

_IDS_RULES_INFO = [
    "ET POLICY DNS Query to .com TLD",
    "ET POLICY HTTP connection to known CDN",
    "ET INFO Outbound TLS 1.3 Connection",
    "ET POLICY External SSH connection",
    "ET INFO GENERIC ICMP Echo Request",
    "GPL ICMP_INFO Echo Reply",
    "ET POLICY Curl User-Agent Outbound",
    "ET INFO Session Traversal Utilities for NAT",
]

_SECURITY_EVENTS_NORMAL = [
    {"alert_name": "Group Policy Applied", "action": "log", "source": "Group Policy"},
    {"alert_name": "Antivirus Scan Completed", "action": "log", "source": "Endpoint Protection"},
    {"alert_name": "Security Baseline Check Passed", "action": "log", "source": "Compliance"},
    {"alert_name": "Windows Defender Definition Updated", "action": "log", "source": "Endpoint Protection"},
    {"alert_name": "Certificate Renewal Successful", "action": "log", "source": "PKI"},
    {"alert_name": "Backup Verification Passed", "action": "log", "source": "Backup Service"},
    {"alert_name": "Disk Encryption Status: Compliant", "action": "log", "source": "BitLocker"},
    {"alert_name": "Firewall Profile Applied", "action": "log", "source": "Windows Firewall"},
]

# Intensity presets: events per user per hour (approximate)
_INTENSITY_MAP = {
    "low": 3,
    "normal": 8,
    "high": 15,
}


class NormalActivityGenerator:
    """Generates realistic benign network activity events.

    Parameters
    ----------
    environment : EnvironmentBuilder
        A loaded environment instance providing hosts and users.
    seed : int, optional
        Random seed for reproducibility.
    """

    def __init__(self, environment: EnvironmentBuilder, seed: Optional[int] = None):
        self._env = environment
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_activity(
        self,
        duration_minutes: int,
        intensity: str = "normal",
        start_time: Optional[datetime] = None,
    ) -> List[Dict]:
        """Generate a list of normal activity events.

        Parameters
        ----------
        duration_minutes : int
            Length of the simulated time window in minutes.
        intensity : str
            One of ``"low"``, ``"normal"``, or ``"high"``.
        start_time : datetime, optional
            Start of the simulation window.  Defaults to *now*.

        Returns
        -------
        list[dict]
            Chronologically sorted list of event dictionaries.
        """
        start = start_time or datetime.now()
        end = start + timedelta(minutes=duration_minutes)
        events_per_user_hour = _INTENSITY_MAP.get(intensity, _INTENSITY_MAP["normal"])

        events: List[Dict] = []
        users = self._env.get_users()

        for user_id, user in users.items():
            host = self._env.get_user_host(user_id)
            if host is None:
                # IT admins without a fixed host use the AD server
                host = self._env.get_host("srv-ad-01") or {}

            user_events = self._generate_user_activity(
                user, host, start, end, events_per_user_hour
            )
            events.extend(user_events)

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ------------------------------------------------------------------
    # Internal generators
    # ------------------------------------------------------------------

    def _generate_user_activity(
        self,
        user: Dict,
        host: Dict,
        start: datetime,
        end: datetime,
        events_per_hour: int,
    ) -> List[Dict]:
        """Create activity events for a single user within the window."""
        events: List[Dict] = []
        work_start, work_end = self._parse_work_hours(user, start)
        window_start = max(start, work_start)
        window_end = min(end, work_end)
        if window_start >= window_end:
            return events

        duration_hours = (window_end - window_start).total_seconds() / 3600
        total_events = max(1, int(duration_hours * events_per_hour))

        # Generate a login at the beginning of the work window
        events.append(self._make_event(
            timestamp=window_start + timedelta(seconds=self._rng.randint(0, 120)),
            host=host,
            user=user,
            event_type="login",
            description=f"User {user['id']} logged in to {host.get('hostname', 'unknown')}",
            details={"method": "password", "domain": "cybertwin.local"},
        ))

        # Distribute random activity events across the work window
        generators = self._get_generators_for_user(user)
        for _ in range(total_events):
            offset_seconds = self._rng.randint(0, int((window_end - window_start).total_seconds()))
            ts = window_start + timedelta(seconds=offset_seconds)
            gen_func = self._rng.choice(generators)
            events.append(gen_func(ts, host, user))

        # Generate a logout near the end of the work window
        events.append(self._make_event(
            timestamp=window_end - timedelta(seconds=self._rng.randint(0, 120)),
            host=host,
            user=user,
            event_type="logout",
            description=f"User {user['id']} logged out of {host.get('hostname', 'unknown')}",
            details={"session_duration_minutes": int(duration_hours * 60)},
        ))

        return events

    def _get_generators_for_user(self, user: Dict):
        """Return a weighted list of event generators based on access rights."""
        rights = set(user.get("access_rights", []))
        generators = []

        # Everybody browses the web and does DNS
        generators.extend([self._gen_web_browse] * 3)
        generators.extend([self._gen_dns_query] * 2)

        if "email" in rights or "all" in rights:
            generators.extend([self._gen_email_send, self._gen_email_receive] * 2)

        file_related = {"shared_files", "hr_portal", "financial_reports", "git_repos"}
        if rights & file_related or "all" in rights:
            generators.extend([self._gen_file_access] * 3)

        generators.extend([self._gen_application_use] * 2)

        # Firewall ALLOW events for normal outbound traffic
        generators.extend([self._gen_firewall_allow] * 2)

        # Database queries for users with ERP/data access
        db_related = {"erp", "financial_reports", "all"}
        if rights & db_related:
            generators.extend([self._gen_database_query] * 2)

        # IDS info-level events (policy checks, normal traffic signatures)
        generators.append(self._gen_ids_info)

        # Security events (policy applied, AV scans, compliance checks)
        generators.append(self._gen_security_event)

        return generators

    # -- Individual event type generators --------------------------------

    def _gen_web_browse(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        domain = self._rng.choice(_WEB_DOMAINS)
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="web_browse",
            description=f"HTTP(S) request to {domain}",
            details={
                "url": f"https://{domain}/{self._rng.choice(['', 'search', 'page', 'docs'])}",
                "method": "GET",
                "status_code": 200,
                "bytes_transferred": self._rng.randint(1024, 524288),
            },
        )

    def _gen_file_access(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        dept = user.get("department", "IT")
        paths = _FILE_PATHS.get(dept, _FILE_PATHS["IT"])
        path = self._rng.choice(paths)
        action = self._rng.choice(["read", "read", "read", "write", "create"])
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="file_access",
            description=f"File {action}: {path}",
            details={"path": path, "action": action, "size_bytes": self._rng.randint(512, 2097152)},
        )

    def _gen_email_send(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        subject_tpl = self._rng.choice(_EMAIL_SUBJECTS_INTERNAL + _EMAIL_SUBJECTS_EXTERNAL)
        subject = subject_tpl.format(date=ts.strftime("%Y-%m-%d"), num=self._rng.randint(1000, 9999))
        users_list = list(self._env.get_users().values())
        recipient = self._rng.choice(users_list)
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="email_send",
            description=f"Email sent to {recipient['email']}: {subject}",
            details={
                "from": user["email"],
                "to": recipient["email"],
                "subject": subject,
                "has_attachment": self._rng.random() < 0.15,
                "size_bytes": self._rng.randint(2048, 1048576),
            },
        )

    def _gen_email_receive(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        subject_tpl = self._rng.choice(_EMAIL_SUBJECTS_INTERNAL + _EMAIL_SUBJECTS_EXTERNAL)
        subject = subject_tpl.format(date=ts.strftime("%Y-%m-%d"), num=self._rng.randint(1000, 9999))
        users_list = list(self._env.get_users().values())
        sender = self._rng.choice(users_list)
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="email_receive",
            description=f"Email received from {sender['email']}: {subject}",
            details={
                "from": sender["email"],
                "to": user["email"],
                "subject": subject,
                "has_attachment": self._rng.random() < 0.15,
                "size_bytes": self._rng.randint(2048, 1048576),
            },
        )

    def _gen_application_use(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        dept = user.get("department", "IT")
        apps = _APPLICATIONS.get(dept, _APPLICATIONS["IT"])
        app = self._rng.choice(apps)
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="application_use",
            description=f"Application launched: {app}",
            details={
                "application": app,
                "action": self._rng.choice(["open", "focus", "save", "close"]),
                "pid": self._rng.randint(1000, 65535),
            },
        )

    def _gen_dns_query(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        domain = self._rng.choice(_WEB_DOMAINS + _DNS_INTERNAL)
        query_type = "A" if self._rng.random() < 0.85 else "AAAA"
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="dns_query",
            description=f"DNS {query_type} query for {domain}",
            details={
                "query": domain,
                "query_type": query_type,
                "response": f"10.0.1.{self._rng.randint(1, 254)}" if ".local" in domain
                else f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}",
                "ttl": self._rng.choice([60, 300, 600, 3600]),
                "server": "10.0.1.5",
            },
        )

    def _gen_firewall_allow(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        dst_port = self._rng.choice([80, 443, 53, 25, 389, 88, 3389, 22, 5432, 993])
        protocol = "UDP" if dst_port == 53 else "TCP"
        rule = self._rng.choice(_FIREWALL_RULES_NORMAL)
        dst_ip = f"10.0.1.{self._rng.randint(1, 99)}" if dst_port in (389, 88, 5432, 25) \
            else f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="firewall_event",
            description=f"Firewall ALLOW: {host.get('ip', '10.0.1.10')} -> {dst_ip}:{dst_port} ({protocol})",
            details={
                "action": "ALLOW",
                "protocol": protocol,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "rule": rule,
                "zone": "Internal",
                "bytes_sent": self._rng.randint(64, 524288),
            },
        )

    def _gen_database_query(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        dept = user.get("department", "IT")
        query_tpl = self._rng.choice(_DB_QUERIES_NORMAL)
        query = query_tpl.format(dept=dept, user=user.get("id", "unknown"))
        table = self._rng.choice(_DB_TABLES_NORMAL)
        db_name = self._rng.choice(["production", "hr_db", "erp_db", "inventory"])
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="database_query",
            description=f"Database SELECT on {db_name}.{table}",
            details={
                "query": query,
                "database": db_name,
                "table": table,
                "rows_returned": self._rng.randint(0, 500),
                "duration_ms": round(self._rng.uniform(0.5, 150.0), 2),
                "dst_host": "srv-db-01",
                "dst_ip": "10.0.1.51",
            },
        )

    def _gen_ids_info(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        rule_name = self._rng.choice(_IDS_RULES_INFO)
        sid = self._rng.randint(2000000, 2999999)
        dst_ip = f"{self._rng.randint(1, 223)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(1, 254)}"
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="ids_event",
            description=f"IDS INFO: {rule_name}",
            details={
                "rule_name": rule_name,
                "sid": sid,
                "action": "alert",
                "priority": self._rng.choice([3, 4]),
                "classification": "Potentially Bad Traffic",
                "protocol": self._rng.choice(["TCP", "UDP"]),
                "dst_ip": dst_ip,
                "dst_port": self._rng.choice([80, 443, 53, 8080]),
                "sensor": self._rng.choice(["IDS-DMZ-01", "IDS-INT-01", "IDS-WAN-01"]),
            },
        )

    def _gen_security_event(self, ts: datetime, host: Dict, user: Dict) -> Dict:
        sec_event = self._rng.choice(_SECURITY_EVENTS_NORMAL)
        return self._make_event(
            timestamp=ts,
            host=host,
            user=user,
            event_type="security_event",
            description=f"Security: {sec_event['alert_name']}",
            details={
                "alert_name": sec_event["alert_name"],
                "action": sec_event["action"],
                "source": sec_event["source"],
                "risk_score": self._rng.randint(1, 15),
                "confidence": round(self._rng.uniform(0.1, 0.3), 2),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_event(
        timestamp: datetime,
        host: Dict,
        user: Dict,
        event_type: str,
        description: str,
        details: Dict,
    ) -> Dict:
        """Construct a standardised event dictionary."""
        return {
            "timestamp": timestamp.isoformat(),
            "event_id": str(uuid.uuid4()),
            "src_host": host.get("id", "unknown"),
            "src_ip": host.get("ip", "0.0.0.0"),
            "user": user.get("id", "unknown"),
            "event_type": event_type,
            "description": description,
            "severity": "info",
            "details": details,
        }

    @staticmethod
    def _parse_work_hours(user: Dict, reference_date: datetime):
        """Return (start, end) datetimes for the user's work hours on *reference_date*."""
        wh = user.get("work_hours", {"start": "09:00", "end": "17:00"})
        sh, sm = (int(x) for x in wh["start"].split(":"))
        eh, em = (int(x) for x in wh["end"].split(":"))
        day = reference_date.replace(hour=0, minute=0, second=0, microsecond=0)
        return (
            day.replace(hour=sh, minute=sm),
            day.replace(hour=eh, minute=em),
        )
