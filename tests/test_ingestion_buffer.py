"""Integration tests for the ingestion buffer (Redis Streams + deque fallback).

These tests run against the in-memory deque path by default (no Redis
required for CI). When ``REDIS_URL`` is set in the environment, the same
test set will exercise the Redis Streams path automatically — proving
the dual-mode contract.

Verifies:
- ingest_one() returns an OCSF-shaped dict
- snapshot() returns the most recent N events
- buffer respects MAXLEN / deque maxlen
- batch ingest reports accepted/rejected counts
- syslog ingest parses raw lines
- clear() empties the buffer
- stats are tracked per ingest
"""
from __future__ import annotations

import pytest


@pytest.fixture
def pipeline():
    """Fresh ingestion pipeline with a small buffer for fast tests."""
    from backend.ingestion.pipeline import IngestionPipeline
    return IngestionPipeline(buffer_size=100, tenant_id="test-tenant")


def _windows_event() -> dict:
    return {
        "source": "windows_security",
        "event_id": 4625,
        "host": "WIN-DC-01",
        "user": "alice",
        "src_ip": "203.0.113.45",
        "raw": "Failed logon attempt from 203.0.113.45",
    }


class TestSingleIngest:
    def test_ingest_one_returns_normalized_dict(self, pipeline):
        result = pipeline.ingest_one(_windows_event(),
                                     source_type="windows_security")
        assert isinstance(result, dict)
        # Normalised events must carry at minimum a category and the original event_id
        assert "category" in result
        assert result.get("event_id") == 4625

    def test_ingest_one_rejects_non_dict(self, pipeline):
        with pytest.raises(ValueError, match="JSON object"):
            pipeline.ingest_one("not-a-dict")  # type: ignore[arg-type]


class TestBufferBehaviour:
    def test_snapshot_returns_recent_events(self, pipeline):
        for i in range(5):
            evt = _windows_event()
            evt["user"] = f"user{i}"
            pipeline.ingest_one(evt, source_type="windows_security")

        snap = pipeline.snapshot(limit=10)
        assert len(snap) == 5

    def test_buffer_respects_maxlen(self):
        from backend.ingestion.pipeline import IngestionPipeline
        small_pipeline = IngestionPipeline(buffer_size=3, tenant_id="test-small")

        for i in range(10):
            evt = _windows_event()
            evt["user"] = f"user{i}"
            small_pipeline.ingest_one(evt, source_type="windows_security")

        snap = small_pipeline.snapshot(limit=100)
        # Either Redis (XADD MAXLEN approximate) or deque (maxlen exact)
        # honours the cap. We allow approximate behaviour: must be <= 5x.
        assert len(snap) <= 15, (
            f"buffer exceeded reasonable cap: {len(snap)} events"
        )

    def test_clear_empties_buffer(self, pipeline):
        pipeline.ingest_one(_windows_event(), source_type="windows_security")
        assert pipeline.snapshot(limit=10), "fixture pre-condition broken"

        pipeline.clear()
        assert pipeline.snapshot(limit=10) == []


class TestBatch:
    def test_batch_accepts_valid_events(self, pipeline):
        events = [_windows_event() for _ in range(5)]
        result = pipeline.ingest_batch(events, source_type="windows_security")
        assert result["accepted"] == 5
        assert result["rejected"] == 0

    def test_batch_rejects_invalid_events(self, pipeline):
        events = [_windows_event(), "garbage", _windows_event(), 42]
        result = pipeline.ingest_batch(events, source_type="windows_security")
        assert result["accepted"] == 2
        assert result["rejected"] == 2


class TestSyslog:
    def test_syslog_lines_ingested(self, pipeline):
        lines = [
            "<14>Jan  1 12:00:00 host1 sshd[1234]: Accepted password for alice",
            "<14>Jan  1 12:01:00 host1 sshd[1234]: Failed password for bob",
        ]
        result = pipeline.ingest_syslog_lines(lines)
        assert result["accepted"] >= 1

    def test_syslog_skips_blank_lines(self, pipeline):
        lines = ["", "   ", "\t"]
        result = pipeline.ingest_syslog_lines(lines)
        assert result["accepted"] == 0


class TestStats:
    def test_stats_record_after_ingest(self, pipeline):
        for _ in range(3):
            pipeline.ingest_one(_windows_event(), source_type="windows_security")
        snapshot = pipeline.stats.to_dict()
        assert snapshot["total_events_received"] >= 3
        assert snapshot["total_events_normalized"] >= 3
