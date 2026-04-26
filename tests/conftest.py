"""
Shared pytest fixtures for CyberTwin SOC test suite.
"""
import os
import pytest

os.environ["AUTH_ADMIN_PASSWORD"]   = os.environ.get("AUTH_ADMIN_PASSWORD",   "cybertwin2024")
os.environ["AUTH_ANALYST_PASSWORD"] = os.environ.get("AUTH_ANALYST_PASSWORD", "soc2024")
os.environ["AUTH_VIEWER_PASSWORD"]  = os.environ.get("AUTH_VIEWER_PASSWORD",  "viewer2024")
os.environ.setdefault("JWT_SECRET", "test-secret-key-minimum-32-chars-long!")


# ---------------------------------------------------------------------------
# Auth fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def admin_token():
    from backend.auth import create_token
    return create_token("admin", "admin")


@pytest.fixture(scope="session")
def analyst_token():
    from backend.auth import create_token
    return create_token("analyst", "analyst")


@pytest.fixture(scope="session")
def viewer_token():
    from backend.auth import create_token
    return create_token("viewer", "viewer")


# ---------------------------------------------------------------------------
# FastAPI TestClient
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from backend.api.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_logs():
    """Minimal log events covering several categories."""
    from datetime import datetime
    ts = datetime.utcnow().isoformat()
    return [
        {"timestamp": ts, "category": "authentication", "event_type": "logon_failure",
         "source_ip": "10.0.0.5", "username": "admin", "host": "DC01"},
        {"timestamp": ts, "category": "process", "event_type": "process_create",
         "process_name": "powershell.exe", "command_line": "powershell -enc SGVsbG8=",
         "host": "WS01", "username": "user1"},
        {"timestamp": ts, "category": "network", "event_type": "connection",
         "dest_ip": "8.8.8.8", "dest_port": 443, "bytes_sent": 512, "host": "WS01"},
        {"timestamp": ts, "category": "file_access", "event_type": "file_write",
         "file_path": "C:\\Windows\\Temp\\payload.exe", "host": "WS01"},
        {"timestamp": ts, "category": "dns", "event_type": "dns_query",
         "query": "c2.evil.com", "host": "WS01"},
        {"timestamp": ts, "category": "security", "event_type": "privilege_escalation",
         "host": "DC01", "username": "user1"},
    ]


@pytest.fixture
def mimikatz_logs():
    """Logs that should trigger the Mimikatz rule."""
    from datetime import datetime
    ts = datetime.utcnow().isoformat()
    return [
        {"timestamp": ts, "category": "process", "event_type": "process_create",
         "process_name": "mimikatz.exe", "command_line": "mimikatz sekurlsa::logonpasswords",
         "host": "DC01", "username": "attacker"},
        {"timestamp": ts, "category": "process", "event_type": "process_create",
         "process_name": "lsass.exe", "command_line": "lsass memory dump",
         "host": "DC01", "username": "SYSTEM"},
    ]


@pytest.fixture
def sample_scenario():
    return {
        "id": "test-scenario-001",
        "name": "Test Scenario",
        "phases": [
            {"name": "Initial Access", "tactic": "initial-access",
             "techniques": ["T1566.001"], "duration_minutes": 5},
            {"name": "Execution", "tactic": "execution",
             "techniques": ["T1059.001"], "duration_minutes": 5},
        ],
        "mitre_techniques_summary": ["T1566.001", "T1059.001", "T1003"],
    }


@pytest.fixture
def sample_alerts():
    return [
        {"rule_id": "RULE-001", "severity": "high", "tactic": "credential-access",
         "technique_id": "T1003", "technique_name": "OS Credential Dumping",
         "timestamp": "2024-01-01T10:05:00"},
        {"rule_id": "RULE-002", "severity": "medium", "tactic": "execution",
         "technique_id": "T1059.001", "technique_name": "PowerShell",
         "timestamp": "2024-01-01T10:03:00"},
    ]
