"""OpenTelemetry distributed tracing setup.

Opt-in via OTEL_ENABLED=true. When enabled, traces are exported to
the configured OTLP endpoint. Prometheus metrics export continues
to work alongside OTel.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("cybertwin.tracing")

_tracer_provider = None


def _otel_available() -> bool:
    try:
        import opentelemetry  # noqa: F401
        return True
    except ImportError:
        return False


def is_tracing_active() -> bool:
    return _tracer_provider is not None


def get_current_trace_id() -> str | None:
    """Return the current OTel trace ID as a hex string, or None."""
    if not is_tracing_active():
        return None
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return None


def init_tracing(app) -> None:
    """Bootstrap OpenTelemetry if OTEL_ENABLED=true.

    Safe to call even when otel packages are not installed — the function
    silently returns so the app can start without tracing.
    """
    global _tracer_provider

    if os.getenv("OTEL_ENABLED", "false").lower() not in ("true", "1", "yes"):
        logger.info("OpenTelemetry tracing disabled (OTEL_ENABLED != true)")
        return

    if not _otel_available():
        logger.warning(
            "OTEL_ENABLED=true but opentelemetry packages are not installed — "
            "skipping tracing setup. Install with: "
            "pip install opentelemetry-api opentelemetry-sdk "
            "opentelemetry-instrumentation-fastapi opentelemetry-exporter-otlp-proto-grpc"
        )
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.propagate import set_global_textmap
        from opentelemetry.propagators.composite import CompositePropagator
        from opentelemetry.trace.propagation import TraceContextTextMapPropagator

        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        resource = Resource.create({"service.name": "cybertwin-soc"})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        set_global_textmap(CompositePropagator([TraceContextTextMapPropagator()]))

        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI auto-instrumentation enabled")

        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument()
            logger.info("SQLAlchemy instrumentation enabled")
        except ImportError:
            logger.debug("opentelemetry-instrumentation-sqlalchemy not installed — skipped")

        try:
            from opentelemetry.instrumentation.redis import RedisInstrumentor
            RedisInstrumentor().instrument()
            logger.info("Redis instrumentation enabled")
        except ImportError:
            logger.debug("opentelemetry-instrumentation-redis not installed — skipped")

        _tracer_provider = provider
        logger.info("OpenTelemetry tracing active → %s", endpoint)

    except Exception:
        logger.exception("Failed to initialise OpenTelemetry tracing")
