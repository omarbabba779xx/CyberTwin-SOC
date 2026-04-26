"""Alert feedback - True Positive / False Positive / Benign analyst votes."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from .database import get_conn
from .models import AlertVerdict, AlertFeedback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_feedback(
    *, alert_id: str, rule_id: str, verdict: str,
    analyst: str, role: str, reason: str = "",
) -> AlertFeedback:
    """Persist analyst feedback on an alert.

    Raises ValueError if `verdict` is not a valid AlertVerdict.
    """
    if verdict not in {v.value for v in AlertVerdict}:
        raise ValueError(f"Invalid verdict '{verdict}'. "
                         f"Allowed: {[v.value for v in AlertVerdict]}")

    ts = _now()
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO alert_feedback
            (alert_id, rule_id, verdict, reason, analyst, role, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (alert_id, rule_id, verdict, reason, analyst, role, ts))
    feedback_id = cur.lastrowid
    conn.commit()
    conn.close()

    return AlertFeedback(
        feedback_id=feedback_id, alert_id=alert_id, rule_id=rule_id,
        verdict=verdict, reason=reason, analyst=analyst, role=role,
        timestamp=ts,
    )


def list_feedback(
    *, alert_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    limit: int = 100,
) -> list[AlertFeedback]:
    """Return recent feedback rows, most-recent first."""
    sql = ["SELECT * FROM alert_feedback WHERE 1=1"]
    params: list = []
    if alert_id:
        sql.append("AND alert_id = ?")
        params.append(alert_id)
    if rule_id:
        sql.append("AND rule_id = ?")
        params.append(rule_id)
    sql.append("ORDER BY feedback_id DESC LIMIT ?")
    params.append(limit)

    conn = get_conn()
    rows = conn.execute(" ".join(sql), params).fetchall()
    conn.close()
    return [AlertFeedback(**dict(r)) for r in rows]


def feedback_summary() -> dict[str, Any]:
    """Aggregate feedback by verdict for the dashboard."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT verdict, COUNT(*) AS n
        FROM alert_feedback
        GROUP BY verdict
    """).fetchall()
    conn.close()
    by_verdict = {r["verdict"]: r["n"] for r in rows}
    total = sum(by_verdict.values())
    fp = by_verdict.get(AlertVerdict.FALSE_POSITIVE.value, 0)
    tp = by_verdict.get(AlertVerdict.TRUE_POSITIVE.value, 0)
    fp_rate = (fp / total) if total else 0.0
    return {
        "total_feedback": total,
        "by_verdict": by_verdict,
        "false_positive_rate": round(fp_rate, 4),
        "true_positive_rate": round(tp / total, 4) if total else 0.0,
    }


def list_noisy_rules(*, min_total: int = 3, fp_threshold: float = 0.5,
                     limit: int = 25) -> list[dict[str, Any]]:
    """Identify rules whose feedback skews towards false positives.

    A rule is "noisy" if it has at least `min_total` feedback rows AND its
    FP rate is at least `fp_threshold`. Returns sorted descending by FP rate.
    """
    conn = get_conn()
    rows = conn.execute("""
        SELECT rule_id, verdict, COUNT(*) AS n
        FROM alert_feedback
        GROUP BY rule_id, verdict
    """).fetchall()
    conn.close()

    by_rule: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by_rule[r["rule_id"]][r["verdict"]] += r["n"]

    out: list[dict[str, Any]] = []
    for rule_id, vmap in by_rule.items():
        total = sum(vmap.values())
        if total < min_total:
            continue
        fp = vmap.get(AlertVerdict.FALSE_POSITIVE.value, 0)
        bp = vmap.get(AlertVerdict.BENIGN_POSITIVE.value, 0)
        rate = (fp + bp) / total
        if rate >= fp_threshold:
            out.append({
                "rule_id": rule_id,
                "total_feedback": total,
                "false_positive": fp,
                "benign_positive": bp,
                "noise_rate": round(rate, 3),
                "by_verdict": dict(vmap),
            })

    out.sort(key=lambda x: x["noise_rate"], reverse=True)
    return out[:limit]
