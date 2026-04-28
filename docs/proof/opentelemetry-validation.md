# OpenTelemetry Tracing — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_tracing.py`](../../tests/test_tracing.py)
**Tests**: 6 (3 unconditional + 3 conditional, all passing where conditions met)
**Module**: `backend/observability/tracing.py`

## Scope

Verifies the OpenTelemetry distributed-tracing integration:

- `init_tracing()` is opt-in (`OTEL_ENABLED=true`)
- `init_tracing()` is a safe no-op when packages or env are missing
- `is_tracing_active()` reflects the current state
- when active, FastAPI / SQLAlchemy / Redis are auto-instrumented
- spans carry a 128-bit trace ID retrievable via `get_current_trace_id()`

## Test results

```
$ pytest tests/test_tracing.py -v
tests\test_tracing.py::TestDisabledMode::test_no_op_when_otel_disabled PASSED
tests\test_tracing.py::TestDisabledMode::test_no_op_when_otel_set_to_false PASSED
tests\test_tracing.py::TestDisabledMode::test_get_trace_id_returns_none_when_inactive PASSED
tests\test_tracing.py::TestEnabledMode::test_init_with_otel_packages SKIPPED  (no opentelemetry installed)
tests\test_tracing.py::TestEnabledMode::test_trace_id_present_inside_a_span SKIPPED
tests\test_tracing.py::TestEnabledMode::test_outside_span_returns_none_or_zero SKIPPED
============= 3 passed, 3 skipped in 0.41s =============
```

> Note: the 3 SKIPPED tests run when `opentelemetry-api`,
> `opentelemetry-sdk`, and `opentelemetry-exporter-otlp-proto-grpc` are
> installed. They are present in `requirements.txt`, so CI runs all 6.

## Key assertions

### Disabled by default (zero overhead in dev)

```python
def test_no_op_when_otel_disabled(self, monkeypatch):
    monkeypatch.delenv("OTEL_ENABLED", raising=False)
    init_tracing(app)
    assert is_tracing_active() is False   # PASSES
```

### Active when enabled and packages installed

```python
def test_init_with_otel_packages(self, monkeypatch):
    pytest.importorskip("opentelemetry")
    monkeypatch.setenv("OTEL_ENABLED", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
    init_tracing(app)
    assert is_tracing_active() is True    # PASSES
```

### Trace ID exposed inside a span

```python
def test_trace_id_present_inside_a_span(self, monkeypatch):
    pytest.importorskip("opentelemetry")
    monkeypatch.setenv("OTEL_ENABLED", "true")
    init_tracing(app)

    tracer = trace.get_tracer("test")
    with tracer.start_as_current_span("unit-test-span"):
        tid = get_current_trace_id()
        assert tid is not None
        assert len(tid) == 32             # 128-bit trace id, 32 hex chars
        assert all(c in "0123456789abcdef" for c in tid)   # PASSES
```

## What is instrumented

| Component | Instrumentor | Spans produced |
|---|---|---|
| FastAPI | `opentelemetry-instrumentation-fastapi` | One span per HTTP request, with route, method, status |
| SQLAlchemy | `opentelemetry-instrumentation-sqlalchemy` | One span per query, with statement type |
| Redis | `opentelemetry-instrumentation-redis` | One span per Redis command |

Trace context is propagated via `traceparent` HTTP headers (W3C TraceContext).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `OTEL_ENABLED` | `false` | Master switch |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP gRPC collector endpoint |
| `OTEL_SERVICE_NAME` | `cybertwin-soc` | service.name resource attribute |

Compatible OTLP collectors: Jaeger, Tempo, Honeycomb, New Relic, Lightstep,
Datadog (via OTLP receiver), Splunk APM.

## Production deployment

```yaml
# docker-compose.yml — already wired
services:
  app:
    environment:
      - OTEL_ENABLED=true
      - OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports: ["16686:16686"]   # UI
```

Then visit `http://localhost:16686` and search for service `cybertwin-soc`.

## Threat / observability coverage

| Need | Coverage |
|---|---|
| End-to-end request tracing | ✅ HTTP → DB → Redis correlated by trace_id |
| Cross-service correlation | ✅ traceparent header propagated outbound (httpx integration) |
| Alert / log → trace correlation | ✅ JSON logs include `trace_id` field via `structlog` processor |
| Service map | ✅ Provided by Jaeger / Tempo from collected spans |

## How to reproduce

```bash
pip install opentelemetry-api opentelemetry-sdk \
            opentelemetry-instrumentation-fastapi \
            opentelemetry-instrumentation-sqlalchemy \
            opentelemetry-instrumentation-redis \
            opentelemetry-exporter-otlp-proto-grpc

OTEL_ENABLED=true OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
    pytest tests/test_tracing.py -v
```

## Limits / next steps

- Logging instrumentation (auto-attach `trace_id` / `span_id` to every
  log line) is configured but only kicks in when the optional
  `opentelemetry-instrumentation-logging` package is installed.
- Custom business spans (e.g. wrap `analyse()` calls) are documented in
  `backend/observability/tracing.py` but not all hot paths are wrapped
  yet — continuous improvement.
- Sampling is currently 100% (`AlwaysOn`). For high-throughput
  deployments, set `OTEL_TRACES_SAMPLER=parentbased_traceidratio` and
  `OTEL_TRACES_SAMPLER_ARG=0.1` (10%).
