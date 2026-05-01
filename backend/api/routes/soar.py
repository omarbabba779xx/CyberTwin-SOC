"""SOAR integration endpoints (TheHive + Cortex) and enterprise connectors."""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.audit import log_action
from backend.auth import require_permission

from ..deps import _client_ip, _get_cached_result, limiter

router = APIRouter(tags=["soar"])


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


@router.get("/api/soar/status")
@limiter.limit("30/minute")
def soar_status(request: Request, user=Depends(require_permission("view_results"))):
    from backend.soar import TheHiveClient, CortexClient
    thehive = TheHiveClient().check_connection()
    cortex = CortexClient().check_connection()
    return {
        "thehive": thehive,
        "cortex": cortex,
        "soar_available": thehive["connected"] or cortex["connected"],
    }


@router.post("/api/soar/push/{result_id}")
@limiter.limit("10/minute")
async def push_to_thehive(
    result_id: str, request: Request,
    user=Depends(require_permission("simulation:run")),
):
    result = _get_cached_result(result_id, tenant_id=_tenant_id(user))
    from backend.soar import TheHiveClient
    loop = asyncio.get_event_loop()
    try:
        push_result = await loop.run_in_executor(
            None, lambda: TheHiveClient().push_simulation_result(result)
        )
        log_action("SOAR_PUSH", username=user["sub"], role=user.get("role"),
                   resource=result_id, ip_address=_client_ip(request),
                   details={"case_id": push_result.get("case_id")})
        return push_result
    except Exception as exc:
        raise HTTPException(502, f"TheHive push failed: {exc}")


@router.post("/api/soar/analyze-iocs/{result_id}")
@limiter.limit("5/minute")
async def analyze_iocs_cortex(
    result_id: str, request: Request,
    user=Depends(require_permission("simulation:run")),
):
    result = _get_cached_result(result_id, tenant_id=_tenant_id(user))
    iocs = result.get("ai_analysis", {}).get("iocs", [])
    if not iocs:
        return {"message": "No IOCs found in this simulation result", "jobs": []}
    from backend.soar import CortexClient
    loop = asyncio.get_event_loop()
    try:
        jobs = await loop.run_in_executor(None, lambda: CortexClient().analyze_iocs(iocs))
        log_action("SOAR_CORTEX", username=user["sub"], role=user.get("role"),
                   resource=result_id, ip_address=_client_ip(request),
                   details={"iocs_submitted": len(jobs)})
        return {"iocs_submitted": len(jobs), "jobs": jobs}
    except Exception as exc:
        raise HTTPException(502, f"Cortex analysis failed: {exc}")


@router.get("/api/soar/analyzers")
@limiter.limit("10/minute")
def list_cortex_analyzers(
    request: Request, data_type: Optional[str] = None,
    user=Depends(require_permission("view_results")),
):
    from backend.soar import CortexClient
    return CortexClient().list_analyzers(data_type=data_type)


@router.get("/api/connectors")
@limiter.limit("60/minute")
def list_enterprise_connectors(
    request: Request,
    user=Depends(require_permission("connector:read")),
):
    from backend.connectors import list_connectors
    return {"connectors": list_connectors()}


@router.get("/api/connectors/{kind}/{name}/check")
@limiter.limit("30/minute")
def check_enterprise_connector(
    kind: str, name: str, request: Request,
    user=Depends(require_permission("connector:read")),
):
    from backend.connectors import get_connector
    from backend.connectors.base import ConnectorError
    try:
        conn = get_connector(kind, name)
    except ConnectorError as exc:
        raise HTTPException(404, str(exc))
    try:
        return conn.check_connection().__dict__
    except NotImplementedError as exc:
        raise HTTPException(501, str(exc))
