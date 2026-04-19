"""
Tests for the CyberTwin SOC TelemetryEngine and LogEvent model.
"""

import pytest
from backend.telemetry.log_generator import TelemetryEngine
from backend.telemetry.models import LogEvent, LogSeverity, LogSource


@pytest.fixture
def engine():
    return TelemetryEngine()


class TestTelemetryEngine:

    def test_auth_event_generates_log(self, engine):
        """An authentication event should produce a LogEvent with log_source=authentication."""
        events = [{"event_type": "authentication", "timestamp": "2024-01-01T10:00:00",
                    "user": "admin", "success": True}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "authentication"

    def test_process_event_generates_log(self, engine):
        """A process event should produce a LogEvent with log_source=process."""
        events = [{"event_type": "process", "timestamp": "2024-01-01T10:00:00",
                    "user": "admin", "process_name": "cmd.exe", "command_line": "cmd.exe /c dir"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "process"

    def test_file_event_generates_log(self, engine):
        """A file_access event should produce a LogEvent with log_source=file_access."""
        events = [{"event_type": "file_access", "timestamp": "2024-01-01T10:00:00",
                    "user": "admin", "action": "read"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "file_access"

    def test_network_event_generates_log(self, engine):
        """A network event should produce a LogEvent with log_source=network."""
        events = [{"event_type": "network", "timestamp": "2024-01-01T10:00:00",
                    "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "network"

    def test_windows_event_ids_present(self, engine):
        """Auth events should have Windows Event IDs (4624 for success, 4625 for failure)."""
        events = [
            {"event_type": "authentication", "timestamp": "2024-01-01T10:00:00",
             "user": "admin", "success": True},
            {"event_type": "authentication", "timestamp": "2024-01-01T10:01:00",
             "user": "admin", "success": False},
        ]
        logs = engine.generate_logs(events)
        event_ids = [log.windows_event_id for log in logs]
        assert 4624 in event_ids
        assert 4625 in event_ids

    def test_sysmon_event_ids_present(self, engine):
        """Process events should have Sysmon Event ID 1 (Process Create)."""
        events = [{"event_type": "process", "timestamp": "2024-01-01T10:00:00",
                    "user": "admin", "process_name": "cmd.exe"}]
        logs = engine.generate_logs(events)
        assert logs[0].sysmon_event_id == 1

    def test_unknown_event_type_uses_generic(self, engine):
        """An unrecognised event_type should still produce a log via generic handler."""
        events = [{"event_type": "some_unknown_type", "timestamp": "2024-01-01T10:00:00"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1

    def test_dns_event_generates_log(self, engine):
        """A dns event should produce a LogEvent with log_source=dns."""
        events = [{"event_type": "dns", "timestamp": "2024-01-01T10:00:00",
                    "domain": "example.com"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "dns"

    def test_firewall_event_generates_log(self, engine):
        """A firewall event should produce a LogEvent with log_source=firewall."""
        events = [{"event_type": "firewall", "timestamp": "2024-01-01T10:00:00",
                    "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10", "action": "ALLOW"}]
        logs = engine.generate_logs(events)
        assert len(logs) >= 1
        assert logs[0].log_source == "firewall"

    def test_malicious_flag_propagated(self, engine):
        """The is_malicious flag should be preserved in the generated log."""
        events = [{"event_type": "process", "timestamp": "2024-01-01T10:00:00",
                    "is_malicious": True, "technique_id": "T1059"}]
        logs = engine.generate_logs(events)
        assert logs[0].is_malicious is True
        assert logs[0].technique_id == "T1059"

    def test_get_statistics(self, engine):
        """get_statistics should return counts by type, severity, and host."""
        events = [
            {"event_type": "authentication", "timestamp": "2024-01-01T10:00:00", "success": True},
            {"event_type": "process", "timestamp": "2024-01-01T10:01:00"},
            {"event_type": "network", "timestamp": "2024-01-01T10:02:00"},
        ]
        engine.generate_logs(events)
        stats = engine.get_statistics()
        assert stats["total_logs"] == 3
        assert "by_type" in stats
        assert "by_severity" in stats


class TestLogEventModel:

    def test_to_dict_returns_all_fields(self):
        """LogEvent.to_dict() should contain all expected keys."""
        log = LogEvent(
            timestamp="2024-01-01T10:00:00.000Z",
            log_source="authentication",
            event_type="logon_success",
            user="admin",
        )
        d = log.to_dict()
        expected_keys = {
            "timestamp", "event_id", "log_source", "event_type", "severity",
            "src_host", "src_ip", "dst_host", "dst_ip", "user", "process_name",
            "command_line", "description", "raw_data", "tags", "technique_id",
            "scenario_id", "is_malicious", "windows_event_id", "sysmon_event_id",
            "event_source", "event_id_description",
        }
        assert expected_keys.issubset(d.keys())

    def test_log_severity_enum(self):
        """LogSeverity enum should contain expected levels."""
        assert LogSeverity.INFO.value == "info"
        assert LogSeverity.CRITICAL.value == "critical"

    def test_log_source_enum(self):
        """LogSource enum should contain expected sources."""
        assert LogSource.AUTHENTICATION.value == "authentication"
        assert LogSource.PROCESS.value == "process"
        assert LogSource.NETWORK.value == "network"
