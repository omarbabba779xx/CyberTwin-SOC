"""Prometheus metrics for CyberTwin SOC.

Exposed via GET /api/metrics (text/plain; version=0.0.4).
"""

from __future__ import annotations

import time
from typing import Awaitable, Callable

from prometheus_client import (
    CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# Use a dedicated registry so multiple imports stay idempotent in tests
METRICS_REGISTRY = CollectorRegistry(auto_describe=True)


# ---------------------------------------------------------------------------
# Counters / histograms / gauges
# ---------------------------------------------------------------------------

events_ingested_total = Counter(
    "cybertwin_events_ingested_total",
    "Number of events accepted by the ingestion pipeline.",
    labelnames=("source_type",),
    registry=METRICS_REGISTRY,
)

events_dropped_total = Counter(
    "cybertwin_events_dropped_total",
    "Events rejected by the ingestion pipeline.",
    labelnames=("reason",),
    registry=METRICS_REGISTRY,
)

rules_matched_total = Counter(
    "cybertwin_rules_matched_total",
    "Detection rule matches across simulations and ingestion.",
    labelnames=("rule_id", "severity"),
    registry=METRICS_REGISTRY,
)

false_positive_feedback_total = Counter(
    "cybertwin_false_positive_feedback_total",
    "Number of analyst feedback votes by verdict.",
    labelnames=("verdict",),
    registry=METRICS_REGISTRY,
)

connector_errors_total = Counter(
    "cybertwin_connector_errors_total",
    "Errors raised by SIEM/SOAR/EDR/ITSM connectors.",
    labelnames=("connector", "error_type"),
    registry=METRICS_REGISTRY,
)

case_sla_breaches_total = Counter(
    "cybertwin_case_sla_breaches_total",
    "Cases that crossed their severity-based SLA without closure.",
    labelnames=("severity",),
    registry=METRICS_REGISTRY,
)

# Histograms

detection_latency_seconds = Histogram(
    "cybertwin_detection_latency_seconds",
    "Time spent in DetectionEngine.analyse().",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=METRICS_REGISTRY,
)

simulation_duration_seconds = Histogram(
    "cybertwin_simulation_duration_seconds",
    "End-to-end simulation duration.",
    buckets=(1, 5, 10, 30, 60, 120, 300),
    registry=METRICS_REGISTRY,
)

ai_analysis_duration_seconds = Histogram(
    "cybertwin_ai_analysis_duration_seconds",
    "Time spent generating AI analyst output.",
    buckets=(0.1, 0.5, 1, 2.5, 5, 10, 30),
    registry=METRICS_REGISTRY,
)

api_request_duration_seconds = Histogram(
    "cybertwin_api_request_duration_seconds",
    "Duration of HTTP requests handled by the API.",
    labelnames=("method", "path_template", "status"),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    registry=METRICS_REGISTRY,
)

# Gauges

active_suppressions_gauge = Gauge(
    "cybertwin_active_suppressions",
    "Currently active suppression rules.",
    registry=METRICS_REGISTRY,
)


# ---------------------------------------------------------------------------
# ASGI middleware that records api_request_duration_seconds
# ---------------------------------------------------------------------------

class MetricsMiddleware(BaseHTTPMiddleware):
    """Records request duration + status for every API call.

    The path template (e.g. `/api/cases/{id}`) is used as the label so we
    don't blow up the cardinality with random IDs.
    """

    async def dispatch(self, request: Request,
                       call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        start = time.perf_counter()
        response: Response | None = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration = time.perf_counter() - start
            # Best-effort path template extraction
            path = request.scope.get("route").path \
                if request.scope.get("route") else request.url.path
            status_code = response.status_code if response else 500
            try:
                api_request_duration_seconds.labels(
                    method=request.method,
                    path_template=path,
                    status=str(status_code),
                ).observe(duration)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def render_metrics() -> tuple[bytes, str]:
    """Return (body, content_type) ready for FastAPI Response."""
    return generate_latest(METRICS_REGISTRY), CONTENT_TYPE_LATEST
