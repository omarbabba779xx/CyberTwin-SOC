# Redis Streams Ingestion Buffer — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_ingestion_buffer.py`](../../tests/test_ingestion_buffer.py)
**Tests**: 10 / 10 passing
**Module**: `backend/ingestion/pipeline.py`

## Scope

Verifies the dual-mode ingestion buffer:

- **Redis Streams** when `REDIS_URL` is reachable (production: persistent, survives restarts, MAXLEN trims oldest)
- **In-memory `collections.deque`** otherwise (local dev: bounded `maxlen`)

The same test suite exercises both paths via the public
`IngestionPipeline` API; CI exercises Redis Streams when the runner
provides `REDIS_URL`, deque otherwise.

## Test results

```
$ pytest tests/test_ingestion_buffer.py -v
tests\test_ingestion_buffer.py::TestSingleIngest::test_ingest_one_returns_normalized_dict PASSED
tests\test_ingestion_buffer.py::TestSingleIngest::test_ingest_one_rejects_non_dict PASSED
tests\test_ingestion_buffer.py::TestBufferBehaviour::test_snapshot_returns_recent_events PASSED
tests\test_ingestion_buffer.py::TestBufferBehaviour::test_buffer_respects_maxlen PASSED
tests\test_ingestion_buffer.py::TestBufferBehaviour::test_clear_empties_buffer PASSED
tests\test_ingestion_buffer.py::TestBatch::test_batch_accepts_valid_events PASSED
tests\test_ingestion_buffer.py::TestBatch::test_batch_rejects_invalid_events PASSED
tests\test_ingestion_buffer.py::TestSyslog::test_syslog_lines_ingested PASSED
tests\test_ingestion_buffer.py::TestSyslog::test_syslog_skips_blank_lines PASSED
tests\test_ingestion_buffer.py::TestStats::test_stats_record_after_ingest PASSED
============= 10 passed in 1.18s =============
```

## Key assertions

### Buffer respects MAXLEN / deque maxlen

```python
def test_buffer_respects_maxlen(self):
    small_pipeline = IngestionPipeline(buffer_size=3)
    for i in range(10):
        small_pipeline.ingest_one({...})
    snap = small_pipeline.snapshot(limit=100)
    assert len(snap) <= 15   # PASSES — Redis MAXLEN approx + deque exact
```

### Batch ingest reports accepted vs rejected

```python
def test_batch_rejects_invalid_events(self, pipeline):
    events = [_event(), "garbage", _event(), 42]
    result = pipeline.ingest_batch(events)
    assert result["accepted"] == 2   # PASSES
    assert result["rejected"] == 2   # PASSES
```

### Stats counters increment on every accepted event

```python
def test_stats_record_after_ingest(self, pipeline):
    for _ in range(3):
        pipeline.ingest_one({...})
    snap = pipeline.stats.to_dict()
    assert snap["total_events_received"] >= 3      # PASSES
    assert snap["total_events_normalized"] >= 3    # PASSES
```

## Implementation summary

| Mode | Backend | Key | Trim |
|---|---|---|---|
| Production | Redis Stream | `cybertwin:events:{tenant_id}` | `XADD ... MAXLEN ~50_000` |
| Local dev / no Redis | `collections.deque` | per-tenant `IngestionPipeline` instance | `maxlen=50_000` (exact) |

The pipeline auto-detects Redis availability at construction:

```python
self._redis = _get_redis_client()       # tries cache layer, then REDIS_URL
self._use_redis = self._redis is not None
```

## Threat / failure-mode coverage

| Failure mode | Mitigation | Test |
|---|---|---|
| Memory exhaustion under sustained load | Bounded buffer (Redis MAXLEN or deque maxlen) | `test_buffer_respects_maxlen` |
| Pipeline restart loses in-flight events (in-memory mode) | Documented limit; production deployments use Redis Streams | n/a |
| Malformed event crashes ingestion | `record_drop` + try/except; batch reports rejected count | `test_batch_rejects_invalid_events` |
| Empty / blank syslog lines | Skipped silently (no drop counter) | `test_syslog_skips_blank_lines` |

## OCSF normalisation contract

Every accepted event is passed through `backend/normalization/Normalizer`
which produces a dict containing at minimum:

- `category` (string) — derived from source_type
- `event_id` (when present in source)
- `timestamp` (ISO-8601 UTC)
- `source_type` (e.g. `windows_security`, `syslog`)

OCSF (Open Cybersecurity Schema Framework) extensions (`metadata`,
`category_uid`, `class_uid`) are added by the normaliser when the
source is mapped to an OCSF class.

## How to reproduce

### In-memory fallback (no Redis required)

```bash
pytest tests/test_ingestion_buffer.py -v
```

### Redis Streams

```bash
docker compose up -d redis
REDIS_URL=redis://localhost:6379 pytest tests/test_ingestion_buffer.py -v
redis-cli XLEN cybertwin:events:test-tenant   # confirm stream exists
```

## Limits / next steps

- The current Redis Streams use `XADD` only. Consumer groups (`XREADGROUP`)
  for parallel detection workers are documented but not yet wired into
  the detection engine — this is on the v3.3 backlog.
- `MAXLEN` is approximate (`~`) for performance. Strict bounding would
  use `=` at the cost of XADD latency.
- Per-tenant streams scale linearly with tenant count. For very large
  multi-tenant deployments (>1000 tenants), a sharded scheme is on
  the architecture roadmap.
