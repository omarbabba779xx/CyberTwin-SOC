"""Shared helpers used by detection rule conditions.

Timestamp parsing, sliding-window grouping, and IP classification.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
]

_ts_cache: dict[str, datetime] = {}


def _parse_ts(ts_str: str) -> datetime:
    """Best-effort timestamp parsing with cache."""
    if ts_str in _ts_cache:
        return _ts_cache[ts_str]
    for fmt in _TS_FORMATS:
        try:
            result = datetime.strptime(ts_str, fmt)
            _ts_cache[ts_str] = result
            return result
        except (ValueError, TypeError):
            continue
    _ts_cache[ts_str] = datetime.min
    return datetime.min


def _events_in_window(
    events: list[dict[str, Any]], window_seconds: int
) -> list[list[dict[str, Any]]]:
    """Group events into sliding windows of *window_seconds*.

    Returns a list of groups where each group contains events that fall
    within the same time window.  Optimised to parse timestamps once.
    """
    if not events:
        return []

    paired = []
    for e in events:
        ts = _parse_ts(e.get("timestamp", ""))
        paired.append((ts, e))
    paired.sort(key=lambda x: x[0])

    groups: list[list[dict[str, Any]]] = []
    n = len(paired)
    for i in range(n):
        anchor_ts = paired[i][0]
        window_end = anchor_ts + timedelta(seconds=window_seconds)
        group = [paired[i][1]]
        for j in range(i + 1, n):
            if paired[j][0] <= window_end:
                group.append(paired[j][1])
            else:
                break  # sorted, so no more events in window
        if len(group) > 1:
            groups.append(group)

    return groups


# RFC 1918 / private-address prefixes
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")


def _is_external_ip(ip: str) -> bool:
    """Return True if *ip* is not in a well-known private range."""
    if not ip:
        return False
    return not ip.startswith(_PRIVATE_PREFIXES)
