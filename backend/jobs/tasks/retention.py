"""Data retention job — purges events and logs beyond configurable age."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.jobs.registry import register_task, update_progress

logger = logging.getLogger("cybertwin.jobs.retention")


@register_task("data_retention")
async def data_retention(task_id: str, **_: Any) -> dict[str, Any]:
    """Delete stale security_events and audit_log rows.

    Configuration (env vars):
      DATA_RETENTION_DAYS  — max age in days (default 90)
      DATABASE_URL         — must be set for this task to operate

    Audit rows with ``status == 'legal_hold'`` are never purged.
    """
    retention_days = int(os.getenv("DATA_RETENTION_DAYS", "90"))
    database_url = os.getenv("DATABASE_URL", "")

    if not database_url:
        logger.info("DATABASE_URL not set — skipping data retention")
        return {"events_purged": 0, "audit_purged": 0}

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    update_progress(task_id, 10)

    from backend.db.session import SessionLocal
    from backend.db.models import SecurityEvent, AuditLog

    session = SessionLocal()
    try:
        events_deleted = (
            session.query(SecurityEvent)
            .filter(SecurityEvent.timestamp < cutoff)
            .delete(synchronize_session=False)
        )
        update_progress(task_id, 50)

        audit_deleted = (
            session.query(AuditLog)
            .filter(AuditLog.timestamp < cutoff)
            .filter(AuditLog.status != "legal_hold")
            .delete(synchronize_session=False)
        )
        update_progress(task_id, 90)

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    logger.info(
        "Data retention complete: %d events purged, %d audit entries purged "
        "(cutoff=%s, retention=%d days)",
        events_deleted,
        audit_deleted,
        cutoff.isoformat(),
        retention_days,
    )
    update_progress(task_id, 100)
    return {"events_purged": events_deleted, "audit_purged": audit_deleted}
