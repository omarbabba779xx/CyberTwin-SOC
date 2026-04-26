"""Suppression rules - silence false positives without deleting them.

Every suppression MUST have an expiration date. There is no permanent
suppression API: this is a deliberate guard against silent rule bypass.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .database import get_conn
from .models import Suppression, SuppressionScope


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_suppression(
    *, scope: str, target: str, reason: str,
    created_by: str, expires_at: Optional[str] = None,
    duration_hours: Optional[int] = None,
    approved_by: Optional[str] = None,
) -> Suppression:
    """Create a suppression. Either `expires_at` (ISO) or `duration_hours` is required.

    Raises:
        ValueError: if scope is invalid, target empty, or no expiration provided.
    """
    if scope not in {s.value for s in SuppressionScope}:
        raise ValueError(f"Invalid scope '{scope}'. "
                         f"Allowed: {[s.value for s in SuppressionScope]}")
    if not target:
        raise ValueError("Suppression target is required.")
    if not reason or len(reason.strip()) < 5:
        raise ValueError("A meaningful reason (>= 5 chars) is required.")
    if not expires_at and not duration_hours:
        raise ValueError("Suppressions MUST expire. "
                         "Provide expires_at (ISO) or duration_hours.")

    if not expires_at:
        expires_at = (_now() + timedelta(hours=duration_hours)).isoformat()
    else:
        # Validate format and that it is in the future
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"expires_at is not a valid ISO timestamp: {exc}")
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt <= _now():
            raise ValueError("expires_at must be in the future.")
        expires_at = exp_dt.isoformat()

    created_at = _now().isoformat()
    conn = get_conn()
    cur = conn.execute("""
        INSERT INTO suppressions
            (scope, target, reason, created_by, created_at, expires_at,
             active, approved_by)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (scope, target, reason, created_by, created_at, expires_at,
          approved_by))
    sid = cur.lastrowid
    conn.commit()
    conn.close()

    return Suppression(
        suppression_id=sid, scope=scope, target=target, reason=reason,
        created_by=created_by, created_at=created_at, expires_at=expires_at,
        active=True, approved_by=approved_by,
    )


def list_suppressions(*, only_active: bool = True) -> list[Suppression]:
    """Return all suppressions; if only_active, hide expired/disabled ones."""
    sql = "SELECT * FROM suppressions"
    if only_active:
        sql += " WHERE active = 1 AND expires_at > ?"
        params = (_now().isoformat(),)
    else:
        params = ()
    sql += " ORDER BY suppression_id DESC"

    conn = get_conn()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    out = []
    for r in rows:
        d = dict(r)
        d["active"] = bool(d["active"])
        out.append(Suppression(**d))
    return out


def delete_suppression(suppression_id: int, *, deleted_by: str) -> bool:
    """Mark a suppression inactive (soft delete preserves audit trail)."""
    conn = get_conn()
    cur = conn.execute(
        "UPDATE suppressions SET active = 0 WHERE suppression_id = ?",
        (suppression_id,),
    )
    conn.commit()
    affected = cur.rowcount
    conn.close()
    return affected > 0


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------

def is_alert_suppressed(alert: dict[str, Any]) -> tuple[bool, Optional[Suppression]]:
    """Check whether an alert matches any active, non-expired suppression.

    Used by the detection pipeline to drop noise without losing the audit
    trail. Returns the matching Suppression if any, so the engine can
    annotate the alert as `suppressed_by=<id>`.
    """
    suppressions = list_suppressions(only_active=True)
    if not suppressions:
        return False, None

    rule_id = (alert.get("rule_id") or "").lower()
    user = (alert.get("affected_user") or "").lower()
    users = {u.lower() for u in alert.get("affected_users", []) if u}
    host = (alert.get("affected_host") or "").lower()
    hosts = {h.lower() for h in alert.get("affected_hosts", []) if h}
    src_ip = (alert.get("src_ip") or "").lower()
    process = ""
    for ev in alert.get("matched_events", []) or []:
        process = (ev.get("process_name") or "").lower()
        if process:
            break

    def _match(target: str, candidates) -> bool:
        t = (target or "").lower()
        if not t:
            return False
        if isinstance(candidates, set):
            return t in candidates
        return t == candidates

    for s in suppressions:
        if s.scope == SuppressionScope.RULE.value and _match(s.target, rule_id):
            return True, s
        if s.scope == SuppressionScope.USER.value and (_match(s.target, user) or _match(s.target, users)):
            return True, s
        if s.scope == SuppressionScope.HOST.value and (_match(s.target, host) or _match(s.target, hosts)):
            return True, s
        if s.scope == SuppressionScope.IP.value and _match(s.target, src_ip):
            return True, s
        if s.scope == SuppressionScope.PROCESS.value and _match(s.target, process):
            return True, s

    return False, None
