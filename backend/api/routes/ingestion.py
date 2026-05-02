"""Live log ingestion endpoints (event, batch, syslog, upload, stats)."""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from backend.audit import log_action
from backend.auth import require_permission

from ..deps import _client_ip, limiter

router = APIRouter(tags=["ingestion"])

_INGEST_MAX_EVENTS = 5000
_INGEST_MAX_EVENT_BYTES = 64 * 1024
_INGEST_MAX_SYSLOG_LINES = 5000
_INGEST_MAX_SYSLOG_LINE_LEN = 8 * 1024


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


def _request_tenant(user: dict, requested_tenant: Optional[str] = None) -> str:
    tenant = _tenant_id(user)
    if requested_tenant and requested_tenant != tenant:
        raise HTTPException(403, "tenant_id in payload does not match authenticated tenant")
    return tenant


def _approx_size(obj: Any) -> int:
    try:
        return len(json.dumps(obj, default=str))
    except Exception:
        return _INGEST_MAX_EVENT_BYTES + 1


class IngestEventRequest(BaseModel):
    event: dict[str, Any]
    source_type: Optional[str] = None
    tenant_id: Optional[str] = None

    @field_validator("event")
    @classmethod
    def _event_size_cap(cls, v):
        if _approx_size(v) > _INGEST_MAX_EVENT_BYTES:
            raise ValueError(f"Event exceeds {_INGEST_MAX_EVENT_BYTES // 1024} KB cap.")
        return v


class IngestBatchRequest(BaseModel):
    events: list[dict[str, Any]]
    source_type: Optional[str] = None
    tenant_id: Optional[str] = None

    @field_validator("events")
    @classmethod
    def _events_size_cap(cls, v):
        if len(v) > _INGEST_MAX_EVENTS:
            raise ValueError(f"Batch capped at {_INGEST_MAX_EVENTS} events.")
        for i, evt in enumerate(v):
            if _approx_size(evt) > _INGEST_MAX_EVENT_BYTES:
                raise ValueError(f"Event #{i} exceeds {_INGEST_MAX_EVENT_BYTES // 1024} KB cap.")
        return v


class IngestSyslogRequest(BaseModel):
    lines: list[str]
    tenant_id: Optional[str] = None

    @field_validator("lines")
    @classmethod
    def _lines_size_cap(cls, v):
        if len(v) > _INGEST_MAX_SYSLOG_LINES:
            raise ValueError(f"Syslog batch capped at {_INGEST_MAX_SYSLOG_LINES} lines.")
        for i, line in enumerate(v):
            if len(line) > _INGEST_MAX_SYSLOG_LINE_LEN:
                raise ValueError(f"Line #{i} exceeds {_INGEST_MAX_SYSLOG_LINE_LEN // 1024} KB cap.")
        return v


@router.post("/api/ingest/event")
@limiter.limit("600/minute")
def ingest_event(payload: IngestEventRequest, request: Request,
                 user=Depends(require_permission("ingestion:write"))):
    from backend.ingestion import get_pipeline
    tenant = _request_tenant(user, payload.tenant_id)
    try:
        ocsf = get_pipeline().ingest_one(
            payload.event, source_type=payload.source_type,
            tenant_id=tenant,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"status": "accepted", "event": ocsf}


@router.post("/api/ingest/batch")
@limiter.limit("60/minute")
def ingest_batch(payload: IngestBatchRequest, request: Request,
                 user=Depends(require_permission("ingestion:write"))):
    from backend.ingestion import get_pipeline
    tenant = _request_tenant(user, payload.tenant_id)
    return get_pipeline().ingest_batch(
        payload.events, source_type=payload.source_type,
        tenant_id=tenant,
    )


@router.post("/api/ingest/syslog")
@limiter.limit("60/minute")
def ingest_syslog(payload: IngestSyslogRequest, request: Request,
                  user=Depends(require_permission("ingestion:write"))):
    from backend.ingestion import get_pipeline
    tenant = _request_tenant(user, payload.tenant_id)
    return get_pipeline().ingest_syslog_lines(payload.lines, tenant_id=tenant)


@router.post("/api/ingest/upload")
@limiter.limit("10/minute")
async def ingest_upload(request: Request, user=Depends(require_permission("ingestion:write"))):
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty body")
    if len(body) > 25 * 1024 * 1024:
        raise HTTPException(413, "File too large (max 25 MB)")
    from backend.ingestion import get_pipeline
    pipeline = get_pipeline()
    tenant = _tenant_id(user)
    accepted = rejected = 0
    for line in body.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
            pipeline.ingest_one(evt, tenant_id=tenant)
            accepted += 1
        except Exception:
            rejected += 1
    log_action("INGEST_UPLOAD", username=user["sub"], role=user.get("role"),
               tenant_id=tenant,
               ip_address=_client_ip(request),
               details={"accepted": accepted, "rejected": rejected})
    return {"accepted": accepted, "rejected": rejected}


@router.get("/api/ingest/stats")
@limiter.limit("60/minute")
def ingest_stats(request: Request, user=Depends(require_permission("ingestion:read"))):
    from backend.ingestion import get_pipeline
    pipe = get_pipeline()
    return {**pipe.stats.to_dict(), "buffer_size": pipe.buffer_size(tenant_id=_tenant_id(user))}


@router.get("/api/ingest/sources")
@limiter.limit("60/minute")
def ingest_supported_sources(request: Request, user=Depends(require_permission("ingestion:read"))):
    from backend.normalization import list_supported
    return {"supported": list_supported()}


@router.get("/api/ingest/health")
@limiter.limit("120/minute")
def ingest_health(request: Request):
    """Public health probe — buffer size and throughput."""
    from backend.ingestion import get_pipeline
    pipe = get_pipeline()
    return {
        "status": "ok",
        "buffer_size": pipe.buffer_size(),
        "events_total": pipe.stats.total_events_received,
        "alerts_total": pipe.stats.total_alerts_generated,
    }


@router.post("/api/ingest/detect")
@limiter.limit("10/minute")
def ingest_detect(request: Request, user=Depends(require_permission("ingestion:read"))):
    """Run the detection engine over the current buffer."""
    from backend.ingestion import get_pipeline
    return get_pipeline().detect(tenant_id=_tenant_id(user))


@router.delete("/api/ingest/buffer")
@limiter.limit("10/minute")
def ingest_clear(request: Request, user=Depends(require_permission("configure_system"))):
    from backend.ingestion import get_pipeline
    get_pipeline().clear(tenant_id=_tenant_id(user))
    log_action("INGEST_CLEAR", username=user["sub"], role=user.get("role"),
               tenant_id=_tenant_id(user),
               ip_address=_client_ip(request))
    return {"status": "cleared"}
