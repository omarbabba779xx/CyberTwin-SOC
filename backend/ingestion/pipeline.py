"""The IngestionPipeline: normalise + buffer + detect + alert.

A single process-wide instance is exposed via `get_pipeline()` and used by
the FastAPI endpoints. The buffer is a bounded deque so we never grow
memory unbounded under sustained load.
"""

from __future__ import annotations

import logging
from collections import deque
from threading import Lock
from typing import Any, Iterable, Optional

from backend.normalization import Normalizer
from .stats import IngestionStats

logger = logging.getLogger("cybertwin.ingestion")

_DEFAULT_BUFFER_SIZE = 50_000   # ~25 MB at 500 B / event


class IngestionPipeline:
    """Normalise raw events, buffer them, and run detection on demand."""

    def __init__(self, buffer_size: int = _DEFAULT_BUFFER_SIZE) -> None:
        self._normalizer = Normalizer()
        self._buffer: deque[dict] = deque(maxlen=buffer_size)
        self._lock = Lock()
        self.stats = IngestionStats()

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def ingest_one(self, raw: dict[str, Any],
                   *, source_type: Optional[str] = None,
                   tenant_id: Optional[str] = None) -> dict[str, Any]:
        """Normalise + buffer a single raw event. Returns the engine-shape dict."""
        if not isinstance(raw, dict):
            self.stats.record_drop("not_a_dict")
            raise ValueError("Event must be a JSON object (dict).")
        try:
            evt = self._normalizer.normalise(raw, source_type=source_type, tenant_id=tenant_id)
        except Exception as exc:
            self.stats.record_drop(f"normalisation:{type(exc).__name__}")
            raise

        engine_evt = evt.to_engine_dict()
        ocsf = evt.to_dict()
        with self._lock:
            self._buffer.append(engine_evt)
        self.stats.record(ocsf)
        return ocsf

    def ingest_batch(self, raws: Iterable[dict[str, Any]],
                     *, source_type: Optional[str] = None,
                     tenant_id: Optional[str] = None) -> dict[str, Any]:
        accepted = 0
        rejected = 0
        for raw in raws:
            try:
                self.ingest_one(raw, source_type=source_type, tenant_id=tenant_id)
                accepted += 1
            except Exception:
                rejected += 1
        return {"accepted": accepted, "rejected": rejected}

    def ingest_syslog_lines(self, lines: Iterable[str],
                            *, tenant_id: Optional[str] = None
                            ) -> dict[str, Any]:
        """Parse and ingest raw syslog text lines."""
        accepted = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                self.ingest_one({"line": line}, source_type="syslog",
                                tenant_id=tenant_id)
                accepted += 1
            except Exception as exc:
                logger.debug("Failed to ingest syslog line: %s", exc)
                self.stats.record_drop("syslog_parse")
        return {"accepted": accepted}

    # ------------------------------------------------------------------
    # Buffer + detection
    # ------------------------------------------------------------------

    def snapshot(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return the last `limit` buffered (engine-shape) events."""
        with self._lock:
            return list(self._buffer)[-limit:]

    def buffer_size(self) -> int:
        with self._lock:
            return len(self._buffer)

    def detect(self) -> dict[str, Any]:
        """Run the detection engine across the current buffer.

        Returns:
            {"alerts": [...], "incidents": [...], "events_analysed": N}
        """
        from backend.detection.engine import DetectionEngine
        with self._lock:
            events = list(self._buffer)
        engine = DetectionEngine(load_sigma=True)
        alerts = engine.analyse(events)
        incidents = engine.correlate_incidents(alerts)
        self.stats.record_alerts(len(alerts))
        return {
            "alerts": alerts,
            "incidents": incidents,
            "events_analysed": len(events),
        }

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_pipeline: Optional[IngestionPipeline] = None


def get_pipeline() -> IngestionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = IngestionPipeline()
    return _pipeline
