"""Static lookup tables used by the AI analyst mixins."""

from __future__ import annotations

_SCENARIO_KEYWORDS: dict[str, list[str]] = {
    "phishing": ["phishing", "spear", "email", "credential_harvest", "lure"],
    "brute_force": ["brute", "password_guess", "credential_access", "spray"],
    "lateral_movement": ["lateral", "pivot", "remote_service", "ssh", "rdp", "smb"],
    "exfiltration": ["exfil", "staging", "archive", "data_theft", "cloud_storage"],
}

_TACTIC_VERB: dict[str, str] = {
    "Initial Access": "gained initial access",
    "Execution": "executed malicious code",
    "Persistence": "established persistence",
    "Privilege Escalation": "escalated privileges",
    "Defense Evasion": "evaded defensive controls",
    "Credential Access": "harvested credentials",
    "Discovery": "performed internal reconnaissance",
    "Lateral Movement": "moved laterally across the network",
    "Collection": "collected sensitive data",
    "Command and Control": "established command-and-control communications",
    "Exfiltration": "exfiltrated data from the environment",
    "Impact": "executed destructive or disruptive actions",
    "Reconnaissance": "conducted external reconnaissance",
    "Resource Development": "developed operational resources",
}
