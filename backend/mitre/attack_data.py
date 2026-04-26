"""
MITRE ATT&CK reference data for CyberTwin SOC.

Contains tactic and technique definitions used by the mapper and scoring engine
to classify detections against the ATT&CK framework.

At import time the full enterprise bundle (~600+ techniques) is merged in from
techniques_bundle.json (if cached). Run `python -m backend.mitre.download_attack`
to populate the cache, or call /api/mitre/sync-taxii from the API.
"""

from collections import OrderedDict
from typing import Dict, Any

# All 14 MITRE ATT&CK tactics in kill-chain order.
MITRE_TACTICS: OrderedDict[str, Dict[str, Any]] = OrderedDict([
    ("TA0043", {
        "name": "Reconnaissance",
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "order": 1,
    }),
    ("TA0042", {
        "name": "Resource Development",
        "description": "The adversary is trying to establish resources they can use to support operations.",
        "order": 2,
    }),
    ("TA0001", {
        "name": "Initial Access",
        "description": "The adversary is trying to get into your network.",
        "order": 3,
    }),
    ("TA0002", {
        "name": "Execution",
        "description": "The adversary is trying to run malicious code.",
        "order": 4,
    }),
    ("TA0003", {
        "name": "Persistence",
        "description": "The adversary is trying to maintain their foothold.",
        "order": 5,
    }),
    ("TA0004", {
        "name": "Privilege Escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "order": 6,
    }),
    ("TA0005", {
        "name": "Defense Evasion",
        "description": "The adversary is trying to avoid being detected.",
        "order": 7,
    }),
    ("TA0006", {
        "name": "Credential Access",
        "description": "The adversary is trying to steal account names and passwords.",
        "order": 8,
    }),
    ("TA0007", {
        "name": "Discovery",
        "description": "The adversary is trying to figure out your environment.",
        "order": 9,
    }),
    ("TA0008", {
        "name": "Lateral Movement",
        "description": "The adversary is trying to move through your environment.",
        "order": 10,
    }),
    ("TA0009", {
        "name": "Collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "order": 11,
    }),
    ("TA0011", {
        "name": "Command and Control",
        "description": "The adversary is trying to communicate with compromised systems to control them.",
        "order": 12,
    }),
    ("TA0010", {
        "name": "Exfiltration",
        "description": "The adversary is trying to steal data.",
        "order": 13,
    }),
    ("TA0040", {
        "name": "Impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "order": 14,
    }),
])

# MITRE ATT&CK techniques relevant to CyberTwin SOC scenarios.
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "TA0001",
        "description": (
            "Adversaries may send spearphishing messages with a malicious link "
            "to elicit sensitive information or gain access to victim systems."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts "
            "as a means of gaining Initial Access, Persistence, Privilege Escalation, "
            "or Defense Evasion."
        ),
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "TA0003",
        "description": (
            "Adversaries may obtain and abuse credentials of a domain account "
            "as a means of gaining persistence."
        ),
    },
    "T1078.003": {
        "name": "Valid Accounts: Local Accounts",
        "tactic": "TA0003",
        "description": (
            "Adversaries may obtain and abuse credentials of a local account "
            "as a means of gaining persistence."
        ),
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "TA0007",
        "description": (
            "Adversaries may enumerate files and directories or search in specific "
            "locations of a host or network share."
        ),
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "TA0009",
        "description": (
            "Adversaries may search local system sources, such as file systems "
            "and configuration files, to find files of interest and sensitive data."
        ),
    },
    "T1048.003": {
        "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic": "TA0010",
        "description": (
            "Adversaries may steal data by exfiltrating it over an un-encrypted "
            "network protocol other than that of the existing command and control channel."
        ),
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0007",
        "description": (
            "Adversaries may attempt to get a listing of services running on "
            "remote hosts and local network infrastructure devices."
        ),
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "TA0006",
        "description": (
            "Adversaries may guess passwords to attempt access to accounts "
            "when knowledge of or access to hashed credentials is unavailable."
        ),
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "TA0004",
        "description": (
            "Adversaries may perform sudo caching and/or use the sudoers file "
            "to elevate privileges on a system."
        ),
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "TA0008",
        "description": (
            "Adversaries may use SSH to login to remote machines and execute "
            "commands for Lateral Movement."
        ),
    },
    "T1195.002": {
        "name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic": "TA0001",
        "description": (
            "Adversaries may manipulate application software prior to receipt "
            "by a final consumer for the purpose of data or system compromise."
        ),
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "TA0003",
        "description": (
            "Adversaries may abuse the cron utility to perform task scheduling "
            "for initial or recurring execution of malicious code."
        ),
    },
    "T1552.004": {
        "name": "Unsecured Credentials: Private Keys",
        "tactic": "TA0006",
        "description": (
            "Adversaries may search for private key certificate files on "
            "compromised systems for insecurely stored credentials."
        ),
    },
    "T1505.003": {
        "name": "Server Software Component: Web Shell",
        "tactic": "TA0003",
        "description": (
            "Adversaries may backdoor web servers with web shells to establish "
            "persistent access to systems."
        ),
    },
    "T1074.001": {
        "name": "Data Staged: Local Data Staging",
        "tactic": "TA0009",
        "description": (
            "Adversaries may stage collected data in a central location or "
            "directory on the local system prior to exfiltration."
        ),
    },
    "T1560.001": {
        "name": "Archive Collected Data: Archive via Utility",
        "tactic": "TA0009",
        "description": (
            "Adversaries may use utilities to compress and/or encrypt "
            "collected data prior to exfiltration."
        ),
    },
    "T1567.002": {
        "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "tactic": "TA0010",
        "description": (
            "Adversaries may exfiltrate data to a cloud storage service "
            "rather than over their primary command and control channel."
        ),
    },
    "T1052.001": {
        "name": "Exfiltration Over Physical Medium: Exfiltration over USB",
        "tactic": "TA0010",
        "description": (
            "Adversaries may attempt to exfiltrate data over a USB "
            "connected physical device."
        ),
    },
    "T1070.004": {
        "name": "Indicator Removal: File Deletion",
        "tactic": "TA0005",
        "description": (
            "Adversaries may delete files left behind by the actions of "
            "their intrusion activity to minimize their footprint."
        ),
    },

    # ---- Credential Access -----------------------------------------------
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006", "description": "Adversaries may attempt to dump credentials to obtain account login and credential material."},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "TA0006", "description": "Adversaries may attempt to access credential material stored in the process memory of LSASS."},
    "T1003.006": {"name": "OS Credential Dumping: DCSync", "tactic": "TA0006", "description": "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's API."},
    "T1110": {"name": "Brute Force", "tactic": "TA0006", "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or hashed."},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "TA0006", "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid credentials."},
    "T1552": {"name": "Unsecured Credentials", "tactic": "TA0006", "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials."},
    "T1552.005": {"name": "Unsecured Credentials: Cloud Instance Metadata API", "tactic": "TA0006", "description": "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data."},
    "T1556": {"name": "Modify Authentication Process", "tactic": "TA0006", "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable unwarranted access to accounts."},
    "T1558.001": {"name": "Steal or Forge Kerberos Tickets: Golden Ticket", "tactic": "TA0006", "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT)."},
    "T1558.002": {"name": "Steal or Forge Kerberos Tickets: Silver Ticket", "tactic": "TA0006", "description": "Adversaries who have the password hash of a target service account may forge Kerberos ticket granting service (TGS) tickets."},
    "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "TA0006", "description": "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket."},
    "T1558.004": {"name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "TA0006", "description": "Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication."},
    "T1550.002": {"name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "TA0008", "description": "Adversaries may 'pass the hash' using stolen password hashes to move laterally within an environment."},

    # ---- Initial Access --------------------------------------------------
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001", "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network."},
    "T1566": {"name": "Phishing", "tactic": "TA0001", "description": "Adversaries may send phishing messages to gain access to victim systems."},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "TA0001", "description": "Adversaries may send spearphishing emails with a malicious attachment."},
    "T1091": {"name": "Replication Through Removable Media", "tactic": "TA0001", "description": "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media."},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001", "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network."},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "TA0001", "description": "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer."},

    # ---- Execution -------------------------------------------------------
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "TA0002", "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
    "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "TA0002", "description": "Adversaries may abuse the Windows command shell for execution."},
    "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactic": "TA0002", "description": "Adversaries may abuse Unix shell commands and scripts for execution."},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "TA0002", "description": "An adversary may rely upon a user opening a malicious file in order to gain execution."},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "TA0002", "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries."},
    "T1610": {"name": "Deploy Container", "tactic": "TA0002", "description": "Adversaries may deploy a container into an environment to facilitate execution or evade defenses."},

    # ---- Persistence -----------------------------------------------------
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "TA0003", "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003", "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code."},
    # T1053.003 (Cron) is defined above with full description.
    "T1136": {"name": "Create Account", "tactic": "TA0003", "description": "Adversaries may create an account to maintain access to victim systems."},
    "T1136.003": {"name": "Create Account: Cloud Account", "tactic": "TA0003", "description": "Adversaries may create a cloud account to maintain access to victim systems."},
    "T1098": {"name": "Account Manipulation", "tactic": "TA0003", "description": "Adversaries may manipulate accounts to maintain access to victim systems."},
    "T1098.002": {"name": "Account Manipulation: Additional Email Delegate Permissions", "tactic": "TA0003", "description": "Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account."},
    "T1098.003": {"name": "Account Manipulation: Additional Cloud Credentials", "tactic": "TA0003", "description": "Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access."},
    "T1207": {"name": "Rogue Domain Controller", "tactic": "TA0005", "description": "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data."},

    # ---- Privilege Escalation -------------------------------------------
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004", "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions."},
    "T1548.005": {"name": "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "tactic": "TA0004", "description": "Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources."},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004", "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges."},
    "T1611": {"name": "Escape to Host", "tactic": "TA0004", "description": "Adversaries may break out of a container to gain access to the underlying host."},

    # ---- Defense Evasion -------------------------------------------------
    "T1055": {"name": "Process Injection", "tactic": "TA0005", "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges."},
    "T1070": {"name": "Indicator Removal", "tactic": "TA0005", "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses."},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactic": "TA0005", "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion."},
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005", "description": "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms."},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "TA0005", "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities."},
    "T1036": {"name": "Masquerading", "tactic": "TA0005", "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools."},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005", "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents."},

    # ---- Discovery -------------------------------------------------------
    "T1087": {"name": "Account Discovery", "tactic": "TA0007", "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment."},
    "T1087.002": {"name": "Account Discovery: Domain Account", "tactic": "TA0007", "description": "Adversaries may attempt to get a listing of domain accounts."},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "TA0007", "description": "Adversaries may attempt to find group and permission settings."},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "TA0007", "description": "Adversaries may attempt to gather information on domain trust relationships."},
    "T1580": {"name": "Cloud Infrastructure Discovery", "tactic": "TA0007", "description": "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment."},
    "T1613": {"name": "Container and Resource Discovery", "tactic": "TA0007", "description": "Adversaries may attempt to discover containers and other resources that are available within a containers environment."},
    "T1595.002": {"name": "Active Scanning: Vulnerability Scanning", "tactic": "TA0043", "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting."},

    # ---- Lateral Movement ------------------------------------------------
    "T1021": {"name": "Remote Services", "tactic": "TA0008", "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections."},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "TA0008", "description": "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB)."},
    "T1021.006": {"name": "Remote Services: Windows Remote Management", "tactic": "TA0008", "description": "Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM)."},

    # ---- Collection ------------------------------------------------------
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "TA0009", "description": "Adversaries may search network shares on computers they have compromised to find files of interest."},
    "T1114": {"name": "Email Collection", "tactic": "TA0009", "description": "Adversaries may target user email to collect sensitive information."},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "TA0009", "description": "Adversaries may access data from cloud storage."},

    # ---- Command & Control -----------------------------------------------
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011", "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering."},
    "T1071.004": {"name": "Application Layer Protocol: DNS", "tactic": "TA0011", "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection."},
    "T1568.002": {"name": "Dynamic Resolution: Domain Generation Algorithms", "tactic": "TA0011", "description": "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for C2."},
    "T1573.001": {"name": "Encrypted Channel: Symmetric Cryptography", "tactic": "TA0011", "description": "Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic."},
    "T1573.002": {"name": "Encrypted Channel: Asymmetric Cryptography", "tactic": "TA0011", "description": "Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic."},

    # ---- Exfiltration ----------------------------------------------------
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010", "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010", "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel."},
    "T1537": {"name": "Transfer Data to Cloud Account", "tactic": "TA0010", "description": "Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account."},
    # T1052.001 (Exfil over USB) is defined above with full description.

    # ---- Impact ----------------------------------------------------------
    "T1485": {"name": "Data Destruction", "tactic": "TA0040", "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network."},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040", "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability."},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040", "description": "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system."},
    "T1496": {"name": "Resource Hijacking", "tactic": "TA0040", "description": "Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems."},
    "T1498": {"name": "Network Denial of Service", "tactic": "TA0040", "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources."},
    "T1498.001": {"name": "Network Denial of Service: Direct Network Flood", "tactic": "TA0040", "description": "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target."},
    "T1498.002": {"name": "Network Denial of Service: Reflection Amplification", "tactic": "TA0040", "description": "Adversaries may attempt to cause a denial of service by reflecting a high-volume of network traffic to a target."},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040", "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services."},
}


# ---------------------------------------------------------------------------
# Auto-merge full MITRE ATT&CK Enterprise bundle (~600 techniques)
# techniques_bundle.json is populated by:
#   python -m backend.mitre.download_attack
# or via /api/mitre/sync-taxii endpoint.
# ---------------------------------------------------------------------------
def _merge_bundle() -> None:
    import logging as _log
    _logger = _log.getLogger("cybertwin.mitre")
    try:
        from pathlib import Path as _Path
        import json as _json
        bundle_file = _Path(__file__).parent / "techniques_bundle.json"
        if not bundle_file.exists():
            return
        data = _json.loads(bundle_file.read_text(encoding="utf-8"))
        added = 0
        for tid, tech in data.get("techniques", {}).items():
            if tid not in MITRE_TECHNIQUES:
                MITRE_TECHNIQUES[tid] = {
                    "name": tech.get("name", ""),
                    "tactic": tech.get("tactic", "TA0001"),
                    "description": tech.get("description", ""),
                    "is_subtechnique": tech.get("is_subtechnique", "." in tid),
                }
                added += 1
        if added:
            _logger.info("MITRE bundle merged: +%d techniques (total %d)", added, len(MITRE_TECHNIQUES))
    except Exception as _exc:
        import logging as _log2
        _log2.getLogger("cybertwin.mitre").warning("Bundle merge failed: %s", _exc)


_merge_bundle()
