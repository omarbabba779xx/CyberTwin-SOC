"""
CyberTwin SOC - Live Log Ingestion (Phase 4)
==============================================
Accepts events from external SIEM, EDR, or log shippers via:

    - JSON over HTTP    (single event or batch)
    - Syslog text       (RFC3164 / RFC5424 lines)
    - File upload       (newline-delimited JSON)

Pipeline:

    raw_event  ->  Normalizer (OCSF)  ->  in-memory ring buffer  ->
        DetectionEngine.analyse()  ->  alerts/incidents

The buffer is bounded to keep memory predictable. Statistics are
exposed via /api/ingest/stats and /api/ingest/health.
"""

from .pipeline import IngestionPipeline, get_pipeline
from .stats import IngestionStats

__all__ = ["IngestionPipeline", "get_pipeline", "IngestionStats"]
