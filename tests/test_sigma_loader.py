"""Unit tests for backend.detection.sigma_loader.

These tests exercise the public surface of `SigmaLoader` (YAML → DetectionRule
conversion + glob matcher) without touching any I/O. They cover:

- Parsing a valid Sigma rule (id, level, tags, logsource, condition).
- Severity mapping (`level` → CyberTwin severity).
- MITRE tag extraction (`attack.txxxx`).
- Logsource → event_type mapping.
- ReDoS-hardened glob matcher: `*` and `?` work, regex metacharacters escape.
- `1 of them`, `any of them`, `all of them` condition selectors.
- Keywords substring matcher.
- `load_directory` over a temp tree (valid + invalid + missing).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.detection.rules import DetectionRule
from backend.detection.sigma_loader import SigmaLoader, _build_condition


# ---------------------------------------------------------------------------
# load_from_yaml
# ---------------------------------------------------------------------------


def test_load_from_yaml_returns_detection_rule():
    yml = """
title: Suspicious cmd.exe child
id: 11111111-2222-3333-4444-555555555555
description: cmd.exe spawns powershell.exe
level: high
tags:
  - attack.execution
  - attack.t1059.003
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    process_name: cmd.exe
    parent_process: explorer.exe
  condition: selection
"""
    rule = SigmaLoader.load_from_yaml(yml)
    assert isinstance(rule, DetectionRule)
    assert rule.severity == "high"
    assert rule.technique_id.startswith("T1059")
    assert rule.tactic.lower() == "execution"
    assert rule.rule_id.startswith("SIGMA-")


@pytest.mark.parametrize(
    "level,expected",
    [
        ("informational", "info"),
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
        ("UNKNOWN_LEVEL", "medium"),  # default fallback
    ],
)
def test_severity_mapping(level: str, expected: str):
    yml = f"""
title: x
detection:
  sel:
    field: v
  condition: sel
level: {level}
logsource:
  product: windows
"""
    rule = SigmaLoader.load_from_yaml(yml)
    assert rule.severity == expected


def test_invalid_yaml_raises_value_error():
    # Top-level scalar — not a mapping.
    with pytest.raises(ValueError):
        SigmaLoader.load_from_yaml("just-a-string")


# ---------------------------------------------------------------------------
# Glob matcher (ReDoS-hardened)
# ---------------------------------------------------------------------------


@pytest.fixture
def cmd_rule():
    """A rule that fires on event_type=process and process_name globs cmd*."""
    detection = {
        "selection": {"process_name": "cmd*"},
        "condition": "selection",
    }
    return _build_condition(detection, logsource_type="process")


def test_glob_full_match_only(cmd_rule):
    events = [
        {"event_type": "process", "process_name": "cmd.exe"},
        {"event_type": "process", "process_name": "cmdline.exe"},  # cmd* matches
        {"event_type": "process", "process_name": "notcmd.exe"},   # tail extra
    ]
    matched = cmd_rule(events)
    names = [e["process_name"] for e in matched]
    assert "cmd.exe" in names
    assert "cmdline.exe" in names
    assert "notcmd.exe" not in names  # full-match required


def test_glob_special_regex_chars_escaped():
    """A `+` or `(` in the pattern must NOT be interpreted as regex."""
    detection = {"sel": {"process_name": "a+b.exe"}, "condition": "sel"}
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "process_name": "a+b.exe"},
        {"event_type": "process", "process_name": "ab.exe"},     # would match 'a+b' as regex
        {"event_type": "process", "process_name": "aab.exe"},
    ])
    names = [e["process_name"] for e in matched]
    assert names == ["a+b.exe"]


def test_question_mark_glob_matches_single_char():
    detection = {"sel": {"file": "log?.txt"}, "condition": "sel"}
    fn = _build_condition(detection, logsource_type="")
    matched = fn([
        {"file": "log1.txt"},
        {"file": "log12.txt"},  # ? = exactly one char
        {"file": "log.txt"},
    ])
    files = [e["file"] for e in matched]
    assert files == ["log1.txt"]


# ---------------------------------------------------------------------------
# Condition selectors
# ---------------------------------------------------------------------------


def test_condition_one_of_them():
    detection = {
        "sel_a": {"process_name": "powershell.exe"},
        "sel_b": {"process_name": "cmd.exe"},
        "condition": "1 of them",
    }
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "process_name": "cmd.exe"},
        {"event_type": "process", "process_name": "explorer.exe"},
        {"event_type": "process", "process_name": "powershell.exe"},
    ])
    assert len(matched) == 2


def test_condition_all_of_them():
    detection = {
        "sel_a": {"process_name": "cmd.exe"},
        "sel_b": {"user": "attacker"},
        "condition": "all of them",
    }
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "process_name": "cmd.exe", "user": "attacker"},
        {"event_type": "process", "process_name": "cmd.exe", "user": "alice"},
    ])
    users = [e["user"] for e in matched]
    assert users == ["attacker"]


def test_condition_named_selector():
    detection = {
        "selection": {"process_name": "mimikatz.exe"},
        "condition": "selection",
    }
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "process_name": "mimikatz.exe"},
        {"event_type": "process", "process_name": "notepad.exe"},
    ])
    assert len(matched) == 1
    assert matched[0]["process_name"] == "mimikatz.exe"


def test_keywords_substring_match():
    detection = {
        "selection": {"keywords": ["sekurlsa", "lsadump"]},
        "condition": "selection",
    }
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "command_line": "mimikatz.exe SEKURLSA::logonpasswords"},
        {"event_type": "process", "command_line": "notepad.exe README.md"},
        {"event_type": "process", "command_line": "powershell -c 'Invoke-LSADump'"},
    ])
    assert len(matched) == 2


def test_logsource_filter_skips_unrelated_event_types():
    detection = {"sel": {"process_name": "evil.exe"}, "condition": "sel"}
    fn = _build_condition(detection, logsource_type="process")
    matched = fn([
        {"event_type": "process", "process_name": "evil.exe"},
        {"event_type": "network", "process_name": "evil.exe"},  # filtered out
    ])
    assert len(matched) == 1


# ---------------------------------------------------------------------------
# load_directory
# ---------------------------------------------------------------------------


def test_load_directory_missing_returns_empty(tmp_path: Path):
    rules = SigmaLoader.load_directory(tmp_path / "does_not_exist")
    assert rules == []


def test_load_directory_loads_valid_skips_invalid(tmp_path: Path):
    good = tmp_path / "good.yml"
    good.write_text(
        "title: Test rule\n"
        "level: high\n"
        "tags: [attack.execution, attack.t1059]\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n"
        "  sel: {process_name: bad.exe}\n"
        "  condition: sel\n",
        encoding="utf-8",
    )
    bad = tmp_path / "bad.yml"
    bad.write_text("not: [valid: yaml: at all", encoding="utf-8")

    rules = SigmaLoader.load_directory(tmp_path)
    assert len(rules) == 1
    assert rules[0].severity == "high"
    assert rules[0].technique_id == "T1059"
