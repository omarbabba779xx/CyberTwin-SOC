"""Concrete background tasks.

Today this module is intentionally minimal: only `coverage_recalculate`
is async, as a proof of the pattern. Heavier workloads
(`simulation:run`, `report:export`, `soar:push`) will migrate here in
v3.2 once the worker process is wired.
"""
from __future__ import annotations

import asyncio
from typing import Any

from .registry import register_task, update_progress


@register_task("coverage_recalculate")
async def coverage_recalculate(task_id: str, **_: Any) -> dict[str, Any]:
    """Recompute the MITRE coverage snapshot off the request path.

    Lightweight today, but it scales linearly with rules*scenarios so we
    want it off the API critical path before v3.2 multi-tenant snapshots.
    """
    from backend.api.routes.coverage import _compute_coverage_snapshot, cache, _COVERAGE_CACHE_KEY

    update_progress(task_id, 10)
    if hasattr(cache, "delete"):
        cache.delete(_COVERAGE_CACHE_KEY)

    update_progress(task_id, 30)
    # Cooperative await so the in-process executor doesn't block the loop.
    await asyncio.sleep(0)

    snap = _compute_coverage_snapshot()
    update_progress(task_id, 100)
    return {"summary": snap.get("summary", {}), "records_count": len(snap.get("records", []))}
