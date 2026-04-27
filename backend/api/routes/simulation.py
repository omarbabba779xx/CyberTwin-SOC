"""Simulation trigger (REST + WebSocket) endpoints."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, field_validator

from backend.audit import log_action
from backend.auth import JWT_SECRET, JWT_ALGORITHM, has_permission, require_permission
from backend.cache import cache
from backend.database import save_run
from backend.orchestrator import SimulationOrchestrator

from ..deps import _client_ip, limiter, orchestrator as _orchestrator

logger = logging.getLogger("cybertwin.simulation")

router = APIRouter(tags=["simulation"])


class SimulationRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=80)
    duration_minutes: int = Field(default=60, ge=1, le=240)
    normal_intensity: Literal["low", "normal", "high"] = "normal"

    @field_validator("scenario_id")
    @classmethod
    def _scenario_id_safe(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", v):
            raise ValueError("scenario_id contains unsupported characters")
        return v


class SimulationSummary(BaseModel):
    scenario_id: str
    scenario_name: str
    total_events: int
    total_logs: int
    total_alerts: int
    total_incidents: int
    overall_score: float
    risk_level: str
    maturity_level: str


@router.post("/api/simulate", response_model=SimulationSummary)
@limiter.limit("10/minute")
async def run_simulation(
    request: Request,
    req: SimulationRequest,
    user=Depends(require_permission("simulation:run")),
):
    scenario = _orchestrator.attack_engine.get_scenario(req.scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{req.scenario_id}' not found")

    log_action("RUN_SIMULATION", username=user["sub"], role=user.get("role"),
               resource=req.scenario_id, ip_address=_client_ip(request))

    loop = asyncio.get_event_loop()
    orch = SimulationOrchestrator()
    orch.initialise()
    result = await loop.run_in_executor(
        None,
        lambda: orch.run_simulation(
            scenario_id=req.scenario_id,
            duration_minutes=req.duration_minutes,
            normal_intensity=req.normal_intensity,
        ),
    )

    cache.set(f"result:{req.scenario_id}", result, ttl=7200)

    try:
        save_run(req.scenario_id, scenario.get("name", ""), result)
    except Exception as exc:
        logger.error("DB save failed: %s", exc)

    scores = result["scores"]
    return SimulationSummary(
        scenario_id=req.scenario_id,
        scenario_name=scenario.get("name", ""),
        total_events=result["total_events"],
        total_logs=result["total_logs"],
        total_alerts=len(result["alerts"]),
        total_incidents=len(result["incidents"]),
        overall_score=scores["overall_score"],
        risk_level=scores["risk_level"],
        maturity_level=scores["maturity_level"],
    )


def _websocket_bearer_token(websocket: WebSocket, query_token: str | None) -> tuple[str | None, bool]:
    """Extract bearer token from Sec-WebSocket-Protocol header or legacy query param."""
    protocols = [
        item.strip()
        for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if item.strip()
    ]
    if len(protocols) >= 2 and protocols[0].lower() == "bearer":
        return protocols[1], True
    return query_token, False


@router.websocket("/ws/simulate/{scenario_id}")
async def ws_simulate(websocket: WebSocket, scenario_id: str, token: str | None = None):
    """Stream simulation events in real-time via WebSocket."""
    import jwt as _jwt

    ws_token, used_subprotocol = _websocket_bearer_token(websocket, token)
    if ws_token is None:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    try:
        ws_user = _jwt.decode(ws_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    from backend.auth import is_token_revoked
    jti = ws_user.get("jti")
    if jti and is_token_revoked(jti):
        await websocket.close(code=4001, reason="Token has been revoked")
        return

    if not has_permission(ws_user.get("role", "viewer"), "simulation:run"):
        await websocket.close(code=4003, reason="Permission 'simulation:run' required")
        return

    await websocket.accept(subprotocol="bearer" if used_subprotocol else None)

    try:
        scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
        if scenario is None:
            await websocket.send_json({"type": "error", "message": f"Scenario '{scenario_id}' not found"})
            await websocket.close()
            return

        loop = asyncio.get_event_loop()
        orch = SimulationOrchestrator()
        orch.initialise()
        result = await loop.run_in_executor(
            None,
            lambda: orch.run_simulation(scenario_id=scenario_id, duration_minutes=60)
        )
        cache.set(f"result:{scenario_id}", result, ttl=7200)
        log_action("RUN_SIMULATION_WS", username=ws_user.get("sub", "?"),
                   role=ws_user.get("role", "?"), resource=scenario_id)

        try:
            save_run(scenario_id, scenario.get("name", ""), result)
        except Exception as exc:
            logger.warning("DB save failed for WS run %s: %s", scenario_id, exc)

        logs = result.get("logs", [])
        timeline = result.get("timeline", [])
        alerts = result.get("alerts", [])
        phases = scenario.get("phases", [])
        events = timeline if timeline else logs

        await websocket.send_json({
            "type": "start",
            "scenario": scenario.get("name", scenario_id),
            "scenario_id": scenario_id,
            "total_events": len(events),
            "total_phases": len(phases),
            "severity": scenario.get("severity", "high"),
            "threat_actor": scenario.get("threat_actor", {}).get("name", "Unknown"),
        })
        await asyncio.sleep(0.5)

        alert_idx = 0
        current_phase = 0
        for i, event in enumerate(events):
            progress = round((i + 1) / len(events) * 100, 1)

            if current_phase < len(phases):
                phase_boundary = int((current_phase + 1) / max(len(phases), 1) * len(events))
                if i >= phase_boundary and current_phase < len(phases) - 1:
                    current_phase += 1
                    await websocket.send_json({
                        "type": "phase",
                        "phase_index": current_phase,
                        "phase_name": phases[current_phase].get("name", f"Phase {current_phase + 1}"),
                        "technique_id": phases[current_phase].get("technique_id", ""),
                        "tactic": phases[current_phase].get("tactic", ""),
                    })
                    await asyncio.sleep(0.4)

            await websocket.send_json({
                "type": "event",
                "data": event,
                "index": i,
                "total": len(events),
                "progress": progress,
                "phase": current_phase,
            })

            while alert_idx < len(alerts):
                if alert_idx <= (i * len(alerts) // max(len(events), 1)):
                    await websocket.send_json({
                        "type": "alert",
                        "data": alerts[alert_idx],
                        "alert_index": alert_idx,
                        "total_alerts": len(alerts),
                    })
                    alert_idx += 1
                    await asyncio.sleep(0.2)
                else:
                    break

            if event.get("is_malicious"):
                await asyncio.sleep(0.12)
            else:
                if i % 3 == 0:
                    await asyncio.sleep(0.02)

        for alert in alerts[alert_idx:]:
            await websocket.send_json({
                "type": "alert",
                "data": alert,
                "alert_index": alert_idx,
                "total_alerts": len(alerts),
            })
            alert_idx += 1
            await asyncio.sleep(0.15)

        await asyncio.sleep(0.3)
        for inc in result.get("incidents", []):
            await websocket.send_json({"type": "incident", "data": inc})
            await asyncio.sleep(0.2)

        await asyncio.sleep(0.5)
        await websocket.send_json({"type": "scores", "data": result["scores"]})

        await asyncio.sleep(0.3)
        if result.get("ai_analysis"):
            await websocket.send_json({
                "type": "ai_analysis",
                "data": {
                    "executive_narrative": result["ai_analysis"].get("executive_narrative", ""),
                    "severity_assessment": result["ai_analysis"].get("severity_assessment", ""),
                },
            })

        await asyncio.sleep(0.5)
        await websocket.send_json({"type": "complete", "data": result})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception as exc:
            logger.debug("Could not send WS error frame: %s", exc)
