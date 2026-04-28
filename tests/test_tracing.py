"""Integration tests for OpenTelemetry tracing initialisation.

Verifies:
- init_tracing() is a no-op when OTEL_ENABLED is unset / false
- get_current_trace_id() returns None when tracing is inactive
- init_tracing() does not raise when otel packages are absent
- when otel packages ARE installed and OTEL_ENABLED=true, a TracerProvider
  is configured and recorded spans carry a trace_id
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def reset_tracing_state():
    """Ensure each test starts with a clean tracing state."""
    import backend.observability.tracing as tr
    tr._tracer_provider = None
    yield
    tr._tracer_provider = None


class TestDisabledMode:
    def test_no_op_when_otel_disabled(self, monkeypatch):
        monkeypatch.delenv("OTEL_ENABLED", raising=False)
        from fastapi import FastAPI
        from backend.observability.tracing import init_tracing, is_tracing_active

        app = FastAPI()
        init_tracing(app)

        assert is_tracing_active() is False

    def test_no_op_when_otel_set_to_false(self, monkeypatch):
        monkeypatch.setenv("OTEL_ENABLED", "false")
        from fastapi import FastAPI
        from backend.observability.tracing import init_tracing, is_tracing_active

        app = FastAPI()
        init_tracing(app)
        assert is_tracing_active() is False

    def test_get_trace_id_returns_none_when_inactive(self):
        from backend.observability.tracing import get_current_trace_id
        assert get_current_trace_id() is None


class TestEnabledMode:
    """Only meaningful when opentelemetry is importable in the test env.

    These tests are SKIPPED if opentelemetry is not installed — they are
    NOT failures, they are conditional integration checks.
    """

    def test_init_with_otel_packages(self, monkeypatch):
        pytest.importorskip("opentelemetry")
        pytest.importorskip("opentelemetry.sdk")

        monkeypatch.setenv("OTEL_ENABLED", "true")
        # Use a non-routable OTLP endpoint so the BatchSpanProcessor fails
        # silently rather than blocking on shutdown
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

        from fastapi import FastAPI
        from backend.observability.tracing import init_tracing, is_tracing_active

        app = FastAPI()
        init_tracing(app)
        assert is_tracing_active() is True

    def test_trace_id_present_inside_a_span(self, monkeypatch):
        pytest.importorskip("opentelemetry")
        pytest.importorskip("opentelemetry.sdk")

        monkeypatch.setenv("OTEL_ENABLED", "true")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

        from fastapi import FastAPI
        from opentelemetry import trace
        from backend.observability.tracing import (
            init_tracing, get_current_trace_id,
        )

        app = FastAPI()
        init_tracing(app)

        tracer = trace.get_tracer("test")
        with tracer.start_as_current_span("unit-test-span"):
            tid = get_current_trace_id()
            assert tid is not None
            assert len(tid) == 32  # 128-bit trace id formatted as 32 hex chars
            assert all(c in "0123456789abcdef" for c in tid)

    def test_outside_span_returns_none_or_zero(self, monkeypatch):
        pytest.importorskip("opentelemetry")
        pytest.importorskip("opentelemetry.sdk")

        monkeypatch.setenv("OTEL_ENABLED", "true")
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

        from fastapi import FastAPI
        from backend.observability.tracing import init_tracing, get_current_trace_id

        app = FastAPI()
        init_tracing(app)

        # No active span → either None or all-zero trace id (otel "invalid")
        tid = get_current_trace_id()
        assert tid is None or set(tid) == {"0"}
