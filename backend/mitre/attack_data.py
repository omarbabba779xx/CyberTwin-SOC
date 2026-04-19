"""
MITRE ATT&CK reference data for CyberTwin SOC.

Contains tactic and technique definitions used by the mapper and scoring engine
to classify detections against the ATT&CK framework.
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
}
