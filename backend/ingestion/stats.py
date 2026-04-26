"""Counters and per-source-type rates exposed by /api/ingest/stats."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any


@dataclass
class IngestionStats:
    """Mutable counters for the ingestion pipeline.

    The internal lock is intentionally NOT a dataclass field because
    `dataclasses.asdict()` cannot deepcopy a Lock; we attach it via
    __post_init__ and rebuild the dict manually in `to_dict()`.
    """

    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_events_received: int = 0
    total_events_normalized: int = 0
    total_events_dropped: int = 0
    total_alerts_generated: int = 0
    last_event_at: str = ""

    by_source_type: dict[str, int] = field(default_factory=dict)
    by_category:    dict[str, int] = field(default_factory=dict)
    drops_by_reason: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._lock: Lock = Lock()

    def record(self, evt: dict[str, Any]) -> None:
        with self._lock:
            self.total_events_received += 1
            self.total_events_normalized += 1
            self.last_event_at = datetime.now(timezone.utc).isoformat()
            st = evt.get("source_type", "unknown")
            cat = evt.get("category", "unknown")
            self.by_source_type[st] = self.by_source_type.get(st, 0) + 1
            self.by_category[cat] = self.by_category.get(cat, 0) + 1

    def record_drop(self, reason: str) -> None:
        with self._lock:
            self.total_events_dropped += 1
            self.drops_by_reason[reason] = self.drops_by_reason.get(reason, 0) + 1

    def record_alerts(self, n: int) -> None:
        with self._lock:
            self.total_alerts_generated += n

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "started_at": self.started_at,
                "total_events_received": self.total_events_received,
                "total_events_normalized": self.total_events_normalized,
                "total_events_dropped": self.total_events_dropped,
                "total_alerts_generated": self.total_alerts_generated,
                "last_event_at": self.last_event_at,
                "by_source_type": dict(self.by_source_type),
                "by_category": dict(self.by_category),
                "drops_by_reason": dict(self.drops_by_reason),
            }
