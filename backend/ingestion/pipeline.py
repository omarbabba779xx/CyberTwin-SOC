"""The IngestionPipeline: normalise + buffer + detect + alert.

A single process-wide instance is exposed via `get_pipeline()` and used by
the FastAPI endpoints.  When Redis is reachable the buffer is a Redis Stream
(persistent, survives restarts).  Otherwise we fall back to a bounded
in-memory deque so memory never grows unbounded under sustained load.
"""

from __future__ import annotations

import json
import logging
import os
from collections import deque
from threading import Lock
from typing import Any, Iterable, Optional

from backend.normalization import Normalizer
from .stats import IngestionStats

logger = logging.getLogger("cybertwin.ingestion")

_DEFAULT_BUFFER_SIZE = 50_000   # ~25 MB at 500 B / event
_DEFAULT_TENANT = "default"


def _stream_key(tenant_id: str) -> str:
    return f"cybertwin:events:{tenant_id}"


def _get_redis_client():
    """Try to obtain a usable Redis client.

    1. Re-use the client already held by the cache layer (avoids a second
       connection pool).
    2. Fall back to REDIS_URL if the cache layer is memory-only.
    3. Return *None* when Redis is not available.
    """
    try:
        from backend.cache import cache
        if cache.backend == "redis":
            return cache._r
    except Exception:
        pass

    redis_url = os.getenv("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _redis
            client = _redis.from_url(redis_url, socket_connect_timeout=2,
                                     decode_responses=True)
            client.ping()
            return client
        except Exception as exc:
            logger.warning("Redis Streams: connection failed (%s)", exc)
    return None


class IngestionPipeline:
    """Normalise raw events, buffer them, and run detection on demand."""

    def __init__(self, buffer_size: int = _DEFAULT_BUFFER_SIZE,
                 tenant_id: str = _DEFAULT_TENANT) -> None:
        self._normalizer = Normalizer()
        self._maxlen = buffer_size
        self._tenant_id = tenant_id
        self._stream_key = _stream_key(tenant_id)
        self._buffers: dict[str, deque[dict]] = {
            tenant_id: deque(maxlen=buffer_size),
        }
        self._buffer = self._buffers[tenant_id]
        self.stats = IngestionStats()

        self._redis = _get_redis_client()
        if self._redis is not None:
            self._use_redis = True
            logger.info(
                "Ingestion buffer: Redis Streams (stream=%s, maxlen~%d)",
                self._stream_key, self._maxlen,
            )
        else:
            self._use_redis = False
            logger.info(
                "Ingestion buffer: in-memory deque (maxlen=%d)", self._maxlen,
            )

        self._lock = Lock()

    # ------------------------------------------------------------------
    # Internal helpers — Redis Streams
    # ------------------------------------------------------------------

    def _tenant(self, tenant_id: Optional[str] = None) -> str:
        return tenant_id or self._tenant_id

    def _buffer_for_tenant(self, tenant_id: str) -> deque[dict]:
        if tenant_id not in self._buffers:
            self._buffers[tenant_id] = deque(maxlen=self._maxlen)
        return self._buffers[tenant_id]

    def _redis_add(self, engine_evt: dict, *, tenant_id: str) -> None:
        self._redis.xadd(
            _stream_key(tenant_id),
            {"data": json.dumps(engine_evt, default=str)},
            maxlen=self._maxlen,
            approximate=True,
        )

    @staticmethod
    def _decode_entries(entries: list) -> list[dict[str, Any]]:
        """Convert [(id, {b'data': b'…'}), …] into a list of dicts."""
        out: list[dict[str, Any]] = []
        for _msg_id, fields in entries:
            raw = fields.get("data") or fields.get(b"data")
            if raw is None:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode()
            out.append(json.loads(raw))
        return out

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
        tenant = self._tenant(tenant_id)
        try:
            evt = self._normalizer.normalise(raw, source_type=source_type, tenant_id=tenant)
        except Exception as exc:
            self.stats.record_drop(f"normalisation:{type(exc).__name__}")
            raise

        engine_evt = evt.to_engine_dict()
        ocsf = evt.to_dict()

        if self._use_redis:
            try:
                self._redis_add(engine_evt, tenant_id=tenant)
            except Exception as exc:
                logger.error("Redis XADD failed (%s); event lost", exc)
        else:
            with self._lock:
                self._buffer_for_tenant(tenant).append(engine_evt)

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

    def snapshot(self, limit: int = 200, *, tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Return the last `limit` buffered (engine-shape) events."""
        tenant = self._tenant(tenant_id)
        if self._use_redis:
            try:
                entries = self._redis.xrevrange(
                    _stream_key(tenant), count=limit,
                )
                entries.reverse()
                return self._decode_entries(entries)
            except Exception as exc:
                logger.error("Redis XREVRANGE failed (%s)", exc)
                return []
        with self._lock:
            return list(self._buffer_for_tenant(tenant))[-limit:]

    def buffer_size(self, *, tenant_id: Optional[str] = None) -> int:
        tenant = self._tenant(tenant_id)
        if self._use_redis:
            try:
                return self._redis.xlen(_stream_key(tenant))
            except Exception as exc:
                logger.error("Redis XLEN failed (%s)", exc)
                return 0
        with self._lock:
            return len(self._buffer_for_tenant(tenant))

    def detect(self, *, tenant_id: Optional[str] = None) -> dict[str, Any]:
        """Run the detection engine across the current buffer.

        Returns:
            {"alerts": [...], "incidents": [...], "events_analysed": N}
        """
        from backend.detection.engine import DetectionEngine

        tenant = self._tenant(tenant_id)
        if self._use_redis:
            try:
                entries = self._redis.xrange(_stream_key(tenant))
                events = self._decode_entries(entries)
            except Exception as exc:
                logger.error("Redis XRANGE failed (%s)", exc)
                events = []
        else:
            with self._lock:
                events = list(self._buffer_for_tenant(tenant))

        engine = DetectionEngine(load_sigma=True, tenant_id=tenant)
        alerts = engine.analyse(events)
        incidents = engine.correlate_incidents(alerts)
        self.stats.record_alerts(len(alerts))
        return {
            "alerts": alerts,
            "incidents": incidents,
            "events_analysed": len(events),
        }

    def clear(self, *, tenant_id: Optional[str] = None) -> None:
        tenant = self._tenant(tenant_id)
        if self._use_redis:
            try:
                self._redis.delete(_stream_key(tenant))
                return
            except Exception as exc:
                logger.error("Redis DELETE (stream clear) failed (%s)", exc)
        with self._lock:
            self._buffer_for_tenant(tenant).clear()


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_pipeline: Optional[IngestionPipeline] = None


def get_pipeline() -> IngestionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = IngestionPipeline()
    return _pipeline
