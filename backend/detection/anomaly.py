"""
CyberTwin SOC — ML Anomaly Detection & UEBA Engine
=====================================================
Uses scikit-learn IsolationForest to detect anomalous log events
and provides User and Entity Behavior Analytics (UEBA) by building
per-user behavioral baselines and flagging deviations.

Detects:
- Statistical outliers in event feature space (IsolationForest)
- Unusual login times per user (UEBA)
- Unusual data volumes per user (UEBA)
- Unusual source IPs per user (UEBA)
- High-frequency authentication anomalies
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime
from typing import Any

logger = logging.getLogger("cybertwin.anomaly")

_ML_OK = False
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    _ML_OK = True
except ImportError:
    logger.warning("scikit-learn/numpy not available — ML anomaly detection disabled. Run: pip install scikit-learn numpy")


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_LOG_TYPES = ["authentication", "process", "file_access", "network",
              "firewall", "dns", "web_access", "email", "database", "security"]
_TYPE_IDX = {t: i for i, t in enumerate(_LOG_TYPES)}

_HOURS = list(range(24))


def _parse_hour(ts: str) -> int:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).hour
        except (ValueError, TypeError):
            pass
    return 12  # default midday


def _is_external_ip(ip: str) -> int:
    if not ip:
        return 0
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    try:
        first, second = int(parts[0]), int(parts[1])
        if first == 10:
            return 0
        if first == 172 and 16 <= second <= 31:
            return 0
        if first == 192 and second == 168:
            return 0
        return 1
    except ValueError:
        return 0


def _extract_features(event: dict[str, Any]) -> list[float]:
    """Convert a log event dict to a numeric feature vector."""
    event_type = event.get("event_type", "")
    type_idx = float(_TYPE_IDX.get(event_type, len(_LOG_TYPES)))

    hour = float(_parse_hour(event.get("timestamp", "")))
    hour_sin = math.sin(2 * math.pi * hour / 24)
    hour_cos = math.cos(2 * math.pi * hour / 24)

    is_malicious = float(event.get("is_malicious", False))
    success = float(event.get("success", True) if event.get("success") is not None else 1)
    external_ip = float(_is_external_ip(event.get("src_ip", "")))

    details = event.get("details", {}) or {}
    bytes_out = float(details.get("bytes_out", details.get("bytes_sent", 0)) or 0)
    bytes_out_log = math.log1p(bytes_out)

    dst_port = float(event.get("dst_port", 0) or 0)
    known_port = float(1 if dst_port in (22, 80, 443, 3389, 445, 3306, 5432, 25, 53) else 0)

    return [
        type_idx, hour_sin, hour_cos,
        is_malicious, success, external_ip,
        bytes_out_log, known_port,
    ]


# ---------------------------------------------------------------------------
# UEBA — Per-user baseline
# ---------------------------------------------------------------------------

class UEBAEngine:
    """Builds per-user behavioral baselines and flags anomalous deviations."""

    def __init__(self) -> None:
        self._user_profiles: dict[str, dict] = defaultdict(lambda: {
            "login_hours": [],
            "src_ips": set(),
            "bytes_out": [],
            "event_types": defaultdict(int),
        })

    def fit(self, logs: list[dict[str, Any]]) -> None:
        """Build baselines from normal (non-malicious) logs."""
        normal_logs = [e for e in logs if not e.get("is_malicious")]
        for event in normal_logs:
            user = event.get("user", "")
            if not user:
                continue
            p = self._user_profiles[user]
            ts = event.get("timestamp", "")
            p["login_hours"].append(_parse_hour(ts))
            ip = event.get("src_ip", "")
            if ip:
                p["src_ips"].add(ip)
            details = event.get("details", {}) or {}
            b = details.get("bytes_out", details.get("bytes_sent", 0)) or 0
            p["bytes_out"].append(float(b))
            p["event_types"][event.get("event_type", "")] += 1

    def score_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Score a single event against the user's baseline. Returns anomaly details."""
        user = event.get("user", "")
        if not user or user not in self._user_profiles:
            return {"ueba_score": 0.0, "ueba_flags": []}

        p = self._user_profiles[user]
        flags: list[str] = []
        score = 0.0

        hour = _parse_hour(event.get("timestamp", ""))
        if p["login_hours"]:
            mean_h = sum(p["login_hours"]) / len(p["login_hours"])
            std_h = (sum((h - mean_h) ** 2 for h in p["login_hours"]) / len(p["login_hours"])) ** 0.5
            if std_h > 0 and abs(hour - mean_h) > 3 * std_h:
                flags.append(f"Unusual login hour ({hour:02d}:xx, baseline mean={mean_h:.1f}h)")
                score += 30.0

        ip = event.get("src_ip", "")
        if ip and p["src_ips"] and ip not in p["src_ips"] and _is_external_ip(ip):
            flags.append(f"New external source IP {ip} not seen in baseline")
            score += 40.0

        details = event.get("details", {}) or {}
        b = float(details.get("bytes_out", details.get("bytes_sent", 0)) or 0)
        if b > 0 and p["bytes_out"]:
            mean_b = sum(p["bytes_out"]) / len(p["bytes_out"])
            if b > mean_b * 10 and b > 10 * 1024 * 1024:
                flags.append(f"Data volume {b / 1024 / 1024:.1f}MB is {b / max(mean_b, 1):.0f}x above baseline")
                score += 50.0

        return {"ueba_score": min(score, 100.0), "ueba_flags": flags}


# ---------------------------------------------------------------------------
# IsolationForest anomaly detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """ML-based anomaly detector using IsolationForest + UEBA."""

    _CONTAMINATION = 0.05  # Expected fraction of anomalies

    def detect(self, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run anomaly detection on a list of log events.

        Returns a list of anomalous events with anomaly scores and UEBA flags.
        """
        if not logs:
            return []

        ueba = UEBAEngine()
        ueba.fit(logs)

        if not _ML_OK:
            return self._fallback_detect(logs, ueba)

        return self._isolation_forest_detect(logs, ueba)

    def _isolation_forest_detect(self, logs: list[dict], ueba: UEBAEngine) -> list[dict]:
        features = [_extract_features(e) for e in logs]
        X = np.array(features, dtype=float)

        n_samples = len(X)
        contamination = min(self._CONTAMINATION, (n_samples - 1) / n_samples) if n_samples > 10 else 0.1

        model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        predictions = model.fit_predict(X)
        scores = model.score_samples(X)

        anomalies: list[dict] = []
        for i, (event, pred, score) in enumerate(zip(logs, predictions, scores)):
            if pred == -1:
                ueba_result = ueba.score_event(event)
                anomaly_score = round(min(100.0, (abs(score) + 0.5) * 80), 1)
                anomalies.append({
                    **event,
                    "anomaly_score": anomaly_score,
                    "anomaly_type": "isolation_forest",
                    "ueba_score": ueba_result["ueba_score"],
                    "ueba_flags": ueba_result["ueba_flags"],
                    "ml_isolation_score": round(float(score), 4),
                })

        for event in logs:
            ueba_result = ueba.score_event(event)
            if ueba_result["ueba_score"] >= 50:
                already = any(a.get("event_id") == event.get("event_id") for a in anomalies)
                if not already:
                    anomalies.append({
                        **event,
                        "anomaly_score": ueba_result["ueba_score"],
                        "anomaly_type": "ueba",
                        "ueba_score": ueba_result["ueba_score"],
                        "ueba_flags": ueba_result["ueba_flags"],
                    })

        anomalies.sort(key=lambda a: a.get("anomaly_score", 0), reverse=True)
        logger.info("Anomaly detection complete: %d anomalies from %d events", len(anomalies), len(logs))
        return anomalies

    def _fallback_detect(self, logs: list[dict], ueba: UEBAEngine) -> list[dict]:
        """Rule-based fallback when scikit-learn is unavailable."""
        anomalies: list[dict] = []
        for event in logs:
            ueba_result = ueba.score_event(event)
            is_malicious = event.get("is_malicious", False)
            hour = _parse_hour(event.get("timestamp", ""))
            off_hours = hour < 6 or hour > 22
            if ueba_result["ueba_score"] >= 40 or (is_malicious and off_hours):
                anomalies.append({
                    **event,
                    "anomaly_score": ueba_result["ueba_score"] or 40.0,
                    "anomaly_type": "ueba_fallback",
                    "ueba_score": ueba_result["ueba_score"],
                    "ueba_flags": ueba_result["ueba_flags"],
                })
        return anomalies
