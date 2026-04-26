"""Phase 4 tests: normalisation (OCSF) + ingestion pipeline + endpoints."""

from __future__ import annotations

import json
import pytest


# ---------------------------------------------------------------------------
# Fixtures: real Windows EventID 4625, Sysmon EID 1, syslog SSH
# ---------------------------------------------------------------------------

@pytest.fixture
def windows_4625():
    return {
        "System": {
            "EventID": 4625,
            "Computer": "WS-001",
            "TimeCreated": "2026-04-26T09:30:11.123Z",
        },
        "EventData": {
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "IpAddress": "10.0.0.42",
            "SubjectUserName": "-",
        },
        "Message": "An account failed to log on.",
    }


@pytest.fixture
def windows_4688():
    return {
        "System": {
            "EventID": 4688,
            "Computer": "WS-001",
            "TimeCreated": "2026-04-26T09:31:00Z",
        },
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell -enc SGVsbG8=",
            "ProcessId": "1234",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessId": "999",
            "SubjectUserName": "alice",
        },
    }


@pytest.fixture
def sysmon_event_1():
    return {
        "System": {"EventID": 1, "Computer": "DC01"},
        "EventData": {
            "UtcTime": "2026-04-26T10:00:00Z",
            "Image": "C:\\Windows\\System32\\mimikatz.exe",
            "CommandLine": "mimikatz sekurlsa::logonpasswords",
            "ProcessId": "4321",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessId": "999",
            "User": "DOMAIN\\admin",
            "Hashes": "MD5=abc,SHA256=deadbeef" + "00" * 30,
        },
    }


@pytest.fixture
def syslog_failed_login():
    return {"line": "Apr 26 09:30:11 web01 sshd[12345]: Failed password for invalid user bob from 203.0.113.5 port 51234 ssh2"}


@pytest.fixture
def cloudtrail_console_login_failure():
    return {
        "eventID": "ct-001",
        "eventTime": "2026-04-26T11:00:00Z",
        "eventName": "ConsoleLogin",
        "errorCode": "Failed authentication",
        "sourceIPAddress": "1.2.3.4",
        "awsRegion": "eu-west-3",
        "recipientAccountId": "111122223333",
        "userIdentity": {"userName": "ops-user", "arn": "arn:aws:iam::111122223333:user/ops"},
    }


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

class TestNormalization:

    def test_supported_list(self):
        from backend.normalization import list_supported
        s = list_supported()
        for src in ("windows_event", "sysmon", "syslog", "cloudtrail", "json"):
            assert src in s

    def test_windows_logon_failure(self, windows_4625):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(windows_4625, source_type="windows_event")
        assert evt.category == "authentication"
        assert evt.activity == "logon_failure"
        assert evt.user.name == "alice"
        assert evt.user.domain == "CORP"
        assert evt.src_endpoint.hostname == "WS-001"

    def test_windows_process_create(self, windows_4688):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(windows_4688, source_type="windows_event")
        assert evt.category == "process"
        assert evt.activity == "process_create"
        assert "powershell.exe" in evt.process.name
        assert "powershell -enc" in evt.process.command_line
        assert evt.process.parent_name and "cmd.exe" in evt.process.parent_name
        # to_engine_dict must be compatible with the existing detection engine
        eng = evt.to_engine_dict()
        assert "powershell" in eng["process_name"]
        assert "powershell -enc" in eng["command_line"]

    def test_sysmon_mimikatz(self, sysmon_event_1):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(sysmon_event_1, source_type="sysmon")
        assert evt.activity == "process_create"
        assert evt.process.name and "mimikatz" in evt.process.name
        assert evt.process.command_line and "sekurlsa" in evt.process.command_line
        # SHA-256 must be extracted from the Sysmon Hashes field
        assert evt.process.hash_sha256 is not None
        assert len(evt.process.hash_sha256) >= 8

    def test_syslog_failed_login(self, syslog_failed_login):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(syslog_failed_login, source_type="syslog")
        assert evt.activity == "logon_failure"
        assert evt.user.name == "bob"
        assert evt.network.src_ip == "203.0.113.5"
        assert evt.src_endpoint.hostname == "web01"
        assert evt.process.name == "sshd"

    def test_cloudtrail_login_failure(self, cloudtrail_console_login_failure):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(cloudtrail_console_login_failure,
                                     source_type="cloudtrail")
        assert evt.category == "authentication"
        assert evt.activity == "logon_failure"
        assert evt.cloud.provider == "aws"
        assert evt.cloud.region == "eu-west-3"
        assert evt.src_endpoint.ip == "1.2.3.4"

    def test_generic_fallback(self):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(
            {"user": "alice", "host": "x", "process_name": "bash",
             "command_line": "rm -rf /tmp/x"},
            source_type="json",
        )
        assert evt.user.name == "alice"
        assert evt.process.name == "bash"
        eng = evt.to_engine_dict()
        assert eng["host"] == "x"
        assert eng["process_name"] == "bash"

    def test_unknown_source_uses_generic(self):
        from backend.normalization import Normalizer
        evt = Normalizer().normalise(
            {"user": "x", "host": "y", "made_up_source_marker": True},
            source_type="totally-unknown",
        )
        # Falls back to generic mapper without raising
        assert evt.user.name == "x"

    def test_tenant_propagated(self):
        from backend.normalization import Normalizer
        evt = Normalizer(default_tenant_id="acme").normalise({"a": 1})
        assert evt.tenant_id == "acme"
        evt2 = Normalizer().normalise({"a": 1}, tenant_id="override")
        assert evt2.tenant_id == "override"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class TestPipeline:

    @pytest.fixture(autouse=True)
    def _fresh(self):
        # Reset the singleton between tests
        from backend.ingestion import get_pipeline
        get_pipeline().clear()
        # Reset stats by replacing the singleton's stats object
        from backend.ingestion.stats import IngestionStats
        get_pipeline().stats = IngestionStats()

    def test_ingest_one_buffers(self, windows_4625):
        from backend.ingestion import get_pipeline
        p = get_pipeline()
        p.ingest_one(windows_4625, source_type="windows_event")
        assert p.buffer_size() == 1
        assert p.stats.total_events_received == 1
        assert "windows_event" in p.stats.by_source_type

    def test_ingest_batch(self, windows_4625, windows_4688):
        from backend.ingestion import get_pipeline
        out = get_pipeline().ingest_batch(
            [windows_4625, windows_4688], source_type="windows_event",
        )
        assert out["accepted"] == 2
        assert out["rejected"] == 0

    def test_ingest_batch_rejects_non_dicts(self):
        from backend.ingestion import get_pipeline
        out = get_pipeline().ingest_batch(
            [{"a": 1}, "not a dict", {"b": 2}],  # type: ignore
            source_type="json",
        )
        assert out["accepted"] == 2
        assert out["rejected"] == 1

    def test_ingest_syslog_lines(self, syslog_failed_login):
        from backend.ingestion import get_pipeline
        out = get_pipeline().ingest_syslog_lines([syslog_failed_login["line"], ""])
        assert out["accepted"] == 1
        assert get_pipeline().buffer_size() == 1

    def test_buffer_bounded(self):
        from backend.ingestion.pipeline import IngestionPipeline
        p = IngestionPipeline(buffer_size=5)
        for i in range(20):
            p.ingest_one({"event_id": f"e-{i}", "user": "x", "host": "h"})
        assert p.buffer_size() == 5

    def test_detect_runs(self, windows_4688):
        """Ingested events are exposed to the existing detection engine."""
        from backend.ingestion import get_pipeline
        # Push a few suspicious PowerShell entries
        for _ in range(3):
            get_pipeline().ingest_one(windows_4688, source_type="windows_event")
        out = get_pipeline().detect()
        assert "alerts" in out and "incidents" in out
        assert out["events_analysed"] == 3


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

class TestIngestionAPI:

    @pytest.fixture(autouse=True)
    def _clear_buffer(self):
        from backend.ingestion import get_pipeline
        get_pipeline().clear()
        from backend.ingestion.stats import IngestionStats
        get_pipeline().stats = IngestionStats()

    def test_event_endpoint(self, client, auth_headers, windows_4625):
        r = client.post("/api/ingest/event", headers=auth_headers,
                        json={"event": windows_4625, "source_type": "windows_event"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "accepted"
        assert body["event"]["category"] == "authentication"

    def test_batch_endpoint(self, client, auth_headers, windows_4625, windows_4688):
        r = client.post("/api/ingest/batch", headers=auth_headers, json={
            "events": [windows_4625, windows_4688],
            "source_type": "windows_event",
        })
        assert r.status_code == 200
        assert r.json()["accepted"] == 2

    def test_batch_size_cap(self, client, auth_headers):
        r = client.post("/api/ingest/batch", headers=auth_headers, json={
            "events": [{"x": 1}] * 5001,
        })
        assert r.status_code == 422

    def test_syslog_endpoint(self, client, auth_headers, syslog_failed_login):
        r = client.post("/api/ingest/syslog", headers=auth_headers, json={
            "lines": [syslog_failed_login["line"]],
        })
        assert r.status_code == 200
        assert r.json()["accepted"] == 1

    def test_upload_ndjson(self, client, auth_headers, windows_4688, sysmon_event_1):
        body = (json.dumps({**windows_4688, "source_type": "windows_event"}) +
                "\n" +
                json.dumps({**sysmon_event_1, "source_type": "sysmon"}))
        r = client.post("/api/ingest/upload", headers=auth_headers, data=body)
        assert r.status_code == 200
        assert r.json()["accepted"] == 2

    def test_stats_endpoint(self, client, auth_headers, windows_4625):
        client.post("/api/ingest/event", headers=auth_headers,
                    json={"event": windows_4625, "source_type": "windows_event"})
        r = client.get("/api/ingest/stats", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["total_events_received"] >= 1
        assert "windows_event" in body["by_source_type"]
        assert "buffer_size" in body

    def test_sources_listed(self, client, auth_headers):
        r = client.get("/api/ingest/sources", headers=auth_headers)
        assert r.status_code == 200
        assert "windows_event" in r.json()["supported"]

    def test_health_public(self, client):
        r = client.get("/api/ingest/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_clear_requires_admin(self, client, auth_headers, admin_headers):
        # analyst forbidden
        assert client.delete("/api/ingest/buffer",
                             headers=auth_headers).status_code == 403
        # admin OK
        assert client.delete("/api/ingest/buffer",
                             headers=admin_headers).status_code == 200

    def test_detect_endpoint(self, client, auth_headers, windows_4688):
        client.post("/api/ingest/event", headers=auth_headers,
                    json={"event": windows_4688, "source_type": "windows_event"})
        r = client.post("/api/ingest/detect", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["events_analysed"] >= 1
        assert "alerts" in body
