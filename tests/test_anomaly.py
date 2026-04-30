"""Unit tests for backend.detection.anomaly.

Cover the deterministic surface of the anomaly module without requiring
any specific scikit-learn version behaviour:

- Feature extraction shape (8-element vector).
- `_is_external_ip` for valid / private / invalid inputs.
- `UEBAEngine` flags unusual login hour, new external IP, large data volume.
- `AnomalyDetector.detect` returns sane shape on empty / mixed inputs.
- `_fallback_detect` is exercised when scikit-learn is patched out.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest

from backend.detection import anomaly as anom_mod
from backend.detection.anomaly import (
    AnomalyDetector,
    UEBAEngine,
    _extract_features,
    _is_external_ip,
    _parse_hour,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evt(**kw: Any) -> dict[str, Any]:
    base = {
        "timestamp": "2024-01-01T10:00:00",
        "event_type": "authentication",
        "user": "alice",
        "src_ip": "10.0.0.5",
        "is_malicious": False,
        "success": True,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_extract_features_returns_eight_floats():
    vec = _extract_features(_evt())
    assert len(vec) == 8
    assert all(isinstance(x, float) for x in vec)


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.0.0.5", 0),       # private
        ("172.16.0.1", 0),     # private
        ("192.168.1.1", 0),    # private
        ("8.8.8.8", 1),        # external
        ("203.0.113.5", 1),    # external (TEST-NET-3)
        ("not-an-ip", 0),
        ("", 0),
        ("999.999.999.999", 1),  # int parse OK, ranges don't match private
    ],
)
def test_is_external_ip(ip: str, expected: int):
    assert _is_external_ip(ip) == expected


def test_parse_hour_handles_various_formats():
    assert _parse_hour("2024-01-01T10:30:00") == 10
    assert _parse_hour("2024-01-01 14:00:00") == 14
    # Garbage falls back to the documented default (12).
    assert _parse_hour("not a timestamp") == 12


# ---------------------------------------------------------------------------
# UEBAEngine
# ---------------------------------------------------------------------------


def test_ueba_unknown_user_returns_zero_score():
    engine = UEBAEngine()
    engine.fit([])
    out = engine.score_event(_evt(user="ghost"))
    assert out["ueba_score"] == 0.0
    assert out["ueba_flags"] == []


def test_ueba_flags_unusual_login_hour():
    engine = UEBAEngine()
    # Tight morning-only baseline (08-09-10h) so 3*std stays under 3h.
    baseline = [
        _evt(timestamp=f"2024-01-{day:02d}T0{hour}:00:00")
        for day in range(1, 11) for hour in (8, 9, 10)
    ]
    engine.fit(baseline)
    out = engine.score_event(_evt(timestamp="2024-01-12T03:00:00"))
    assert out["ueba_score"] >= 30.0
    assert any("Unusual login hour" in f for f in out["ueba_flags"])


def test_ueba_flags_new_external_ip():
    engine = UEBAEngine()
    engine.fit([_evt(src_ip="10.0.0.5") for _ in range(5)])
    out = engine.score_event(_evt(src_ip="203.0.113.99"))
    assert out["ueba_score"] >= 40.0
    assert any("New external source IP" in f for f in out["ueba_flags"])


def test_ueba_flags_large_data_volume():
    engine = UEBAEngine()
    baseline = [
        _evt(details={"bytes_out": 1_000}) for _ in range(20)
    ]
    engine.fit(baseline)
    out = engine.score_event(_evt(details={"bytes_out": 200 * 1024 * 1024}))
    assert out["ueba_score"] >= 50.0
    assert any("Data volume" in f for f in out["ueba_flags"])


def test_ueba_score_capped_at_one_hundred():
    engine = UEBAEngine()
    engine.fit([_evt(src_ip="10.0.0.5") for _ in range(5)])
    out = engine.score_event(_evt(
        timestamp="2024-01-01T03:00:00",  # unusual hour
        src_ip="203.0.113.99",            # new external IP
        details={"bytes_out": 500 * 1024 * 1024},
    ))
    assert out["ueba_score"] <= 100.0


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------


def test_detect_empty_logs_returns_empty():
    assert AnomalyDetector().detect([]) == []


def test_detect_mixed_inputs_returns_list_of_dicts():
    """Smoke test: the detector should always return a list of well-shaped dicts."""
    logs = [_evt(user=f"u{i}", timestamp=f"2024-01-01T{i % 24:02d}:00:00")
            for i in range(40)]
    # Inject an obvious outlier: very large data exfil at off-hours.
    logs.append(_evt(
        user="alice",
        timestamp="2024-01-01T03:00:00",
        src_ip="203.0.113.99",
        is_malicious=True,
        details={"bytes_out": 500 * 1024 * 1024},
    ))

    anomalies = AnomalyDetector().detect(logs)
    assert isinstance(anomalies, list)
    for a in anomalies:
        assert "anomaly_score" in a
        assert "anomaly_type" in a
        assert 0.0 <= a["anomaly_score"] <= 100.0


def test_fallback_detect_runs_when_ml_unavailable():
    """Patch the module-level _ML_OK flag so the fallback path runs."""
    logs = [
        _evt(user="alice", timestamp=f"2024-01-{d:02d}T09:00:00") for d in range(1, 11)
    ]
    logs.append(_evt(
        user="alice",
        timestamp="2024-01-12T03:00:00",   # off-hours
        src_ip="203.0.113.99",             # new external IP
        is_malicious=True,
    ))

    with mock.patch.object(anom_mod, "_ML_OK", False):
        anomalies = AnomalyDetector().detect(logs)
    types = {a["anomaly_type"] for a in anomalies}
    # Fallback path is the only one that emits 'ueba_fallback'.
    assert "ueba_fallback" in types
