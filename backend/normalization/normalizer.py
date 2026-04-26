"""Top-level Normalizer: dispatches raw events to the right mapper."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .schema import NormalizedEvent
from . import mappers

logger = logging.getLogger("cybertwin.normalization")


# Registry: source_type -> mapper(raw) -> NormalizedEvent
_REGISTRY: dict[str, Callable[[dict], NormalizedEvent]] = {
    "windows_event": mappers.map_windows_event,
    "windows":       mappers.map_windows_event,
    "sysmon":        mappers.map_sysmon,
    "syslog":        mappers.map_syslog,
    "cloudtrail":    mappers.map_cloudtrail,
    "aws_cloudtrail": mappers.map_cloudtrail,
    "json":          mappers.map_generic_json,
    "generic":       mappers.map_generic_json,
}


def register_mapper(source_type: str,
                    mapper: Callable[[dict], NormalizedEvent]) -> None:
    """Plug a custom mapper at runtime (e.g. for an enterprise source)."""
    _REGISTRY[source_type] = mapper


def list_supported() -> list[str]:
    """Return the source_type identifiers we currently know about."""
    return sorted(_REGISTRY.keys())


class Normalizer:
    """Public facade used by the ingestion endpoints."""

    def __init__(self, default_tenant_id: str = "default") -> None:
        self._tenant = default_tenant_id

    def normalise(self, raw: dict[str, Any],
                  source_type: Optional[str] = None,
                  tenant_id: Optional[str] = None) -> NormalizedEvent:
        """Convert one raw event to a NormalizedEvent.

        Args:
            raw:         The source-shaped event.
            source_type: Override / hint. If absent, we look at the raw event.
            tenant_id:   Multi-tenant tag attached to the event.
        """
        source_type = (source_type or raw.get("source_type") or "json").lower()
        mapper = _REGISTRY.get(source_type, mappers.map_generic_json)
        try:
            evt = mapper(raw)
        except Exception as exc:
            logger.warning("Mapper '%s' failed: %s -- using generic fallback",
                           source_type, exc)
            evt = mappers.map_generic_json(raw)
        evt.tenant_id = tenant_id or self._tenant
        return evt

    def normalise_batch(self, raws: list[dict[str, Any]],
                        source_type: Optional[str] = None,
                        tenant_id: Optional[str] = None,
                        ) -> list[NormalizedEvent]:
        return [self.normalise(r, source_type=source_type, tenant_id=tenant_id)
                for r in raws]
