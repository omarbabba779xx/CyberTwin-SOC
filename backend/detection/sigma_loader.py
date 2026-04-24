"""
CyberTwin SOC — Sigma Rules Loader
=====================================
Parses YAML Sigma rules (https://sigmahq.io/) and converts them into
CyberTwin DetectionRule objects that integrate with the existing
DetectionEngine pipeline.

Supports:
- Sigma condition syntax: 1 of them, all of them, keyword and field matching
- Logsource mapping to CyberTwin event_type
- Severity (level) mapping
- MITRE ATT&CK tag extraction
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

from backend.detection.rules import DetectionRule

logger = logging.getLogger("cybertwin.sigma")

# ---------------------------------------------------------------------------
# Sigma logsource → CyberTwin event_type mapping
# ---------------------------------------------------------------------------

_LOGSOURCE_MAP: dict[str, str] = {
    "windows": "security",
    "windows.security": "security",
    "windows.process_creation": "process",
    "windows.network_connection": "network",
    "windows.file_event": "file_access",
    "windows.dns_query": "dns",
    "linux": "process",
    "linux.network": "network",
    "linux.file": "file_access",
    "web": "web_access",
    "proxy": "web_access",
    "firewall": "firewall",
    "network": "network",
    "dns": "dns",
    "email": "email",
    "cloud": "application",
    "aws.cloudtrail": "application",
    "azure.activitylogs": "application",
}

_SIGMA_TO_SEVERITY: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


# ---------------------------------------------------------------------------
# Condition builder
# ---------------------------------------------------------------------------

def _build_condition(detection: dict[str, Any], logsource_type: str) -> Callable[[list[dict]], list[dict]]:
    """Build a CyberTwin condition function from a Sigma detection block."""

    def _match_event(event: dict, search: dict) -> bool:
        for field, value in search.items():
            if field == "keywords":
                haystack = str(event).lower()
                values = value if isinstance(value, list) else [value]
                if not any(str(v).lower() in haystack for v in values):
                    return False
                continue
            event_val = str(event.get(field, "")).lower()
            values = value if isinstance(value, list) else [value]
            matched = False
            for v in values:
                pattern = str(v).lower().replace("*", ".*")
                if re.search(pattern, event_val):
                    matched = True
                    break
            if not matched:
                return False
        return True

    def _condition_fn(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []
        searches = {k: v for k, v in detection.items() if k != "condition"}
        condition_str = detection.get("condition", "1 of them")

        for event in events:
            if logsource_type and event.get("event_type") not in ("", None, logsource_type):
                continue
            if "1 of them" in condition_str or "any of them" in condition_str:
                if any(_match_event(event, s) if isinstance(s, dict) else False
                       for s in searches.values()):
                    matched.append(event)
            elif "all of them" in condition_str:
                if all(_match_event(event, s) if isinstance(s, dict) else False
                       for s in searches.values()):
                    matched.append(event)
            else:
                for name, search in searches.items():
                    if name in condition_str and isinstance(search, dict):
                        if _match_event(event, search):
                            matched.append(event)
                            break
        return matched

    return _condition_fn


# ---------------------------------------------------------------------------
# SigmaLoader
# ---------------------------------------------------------------------------

class SigmaLoader:
    """Parses Sigma YAML rules and returns DetectionRule objects."""

    @classmethod
    def load_from_yaml(cls, yaml_content: str) -> DetectionRule:
        """Parse a single Sigma rule from YAML string."""
        if not _YAML_OK:
            raise ImportError("PyYAML is required: pip install pyyaml")

        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("Invalid Sigma rule: expected a YAML mapping")

        rule_id = str(data.get("id", f"SIGMA-{hash(yaml_content) & 0xFFFF:04X}"))
        name = data.get("title", "Unnamed Sigma Rule")
        description = data.get("description", name)
        sigma_level = data.get("level", "medium")
        severity = _SIGMA_TO_SEVERITY.get(sigma_level.lower(), "medium")

        # Extract MITRE tags
        tags = data.get("tags", [])
        technique_id = ""
        tactic = ""
        for tag in tags:
            tag_lower = str(tag).lower()
            if tag_lower.startswith("attack.t"):
                tid = tag[7:].upper()
                if not technique_id:
                    technique_id = tid
            elif tag_lower.startswith("attack."):
                tactic_raw = tag[7:].replace("_", " ").title()
                if not tactic:
                    tactic = tactic_raw

        # Logsource
        logsource = data.get("logsource", {})
        ls_key = ".".join(filter(None, [
            logsource.get("product", ""),
            logsource.get("category", logsource.get("service", "")),
        ])).lower()
        event_type = _LOGSOURCE_MAP.get(ls_key, _LOGSOURCE_MAP.get(
            logsource.get("product", "").lower(), ""
        ))

        detection_block = data.get("detection", {})
        condition_fn = _build_condition(detection_block, event_type)

        return DetectionRule(
            rule_id=f"SIGMA-{rule_id[:16]}",
            name=name,
            description=description,
            severity=severity,
            tactic=tactic or "Unknown",
            technique_id=technique_id,
            technique_name=name,
            condition=condition_fn,
        )

    @classmethod
    def load_directory(cls, sigma_dir: Path) -> list[DetectionRule]:
        """Load all .yml Sigma rules from a directory."""
        rules: list[DetectionRule] = []
        if not sigma_dir.exists():
            logger.warning("Sigma rules directory not found: %s", sigma_dir)
            return rules
        for yml_file in sigma_dir.glob("**/*.yml"):
            try:
                rule = cls.load_from_yaml(yml_file.read_text(encoding="utf-8"))
                rules.append(rule)
                logger.info("Loaded Sigma rule: %s (%s)", rule.name, rule.rule_id)
            except Exception as exc:
                logger.warning("Failed to load Sigma rule %s: %s", yml_file, exc)
        logger.info("Loaded %d Sigma rules from %s", len(rules), sigma_dir)
        return rules
