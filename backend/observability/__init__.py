"""
CyberTwin SOC - Observability (Phase 5)
=========================================
Production-grade observability primitives:

  - Prometheus /metrics endpoint with cybertwin_* counters/histograms
  - Structured JSON logging
  - request_id middleware (correlation ID injected into every log line)
  - Deep health probe (/api/health/deep) with dependency status

Designed to be drop-in: existing endpoints keep working, all observability
hooks are additive and non-breaking.
"""

from .metrics import (
    METRICS_REGISTRY, MetricsMiddleware, render_metrics,
    events_ingested_total, detection_latency_seconds, rules_matched_total,
    api_request_duration_seconds, simulation_duration_seconds,
)
from .logging_setup import setup_json_logging
from .middleware import RequestIdMiddleware, request_id_var

__all__ = [
    "METRICS_REGISTRY", "MetricsMiddleware", "render_metrics",
    "events_ingested_total", "detection_latency_seconds", "rules_matched_total",
    "api_request_duration_seconds", "simulation_duration_seconds",
    "setup_json_logging", "RequestIdMiddleware", "request_id_var",
]
