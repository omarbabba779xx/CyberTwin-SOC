"""
CyberTwin SOC - FastAPI Application

REST API + WebSocket — enterprise-grade SOC simulation platform.
Features: bcrypt auth, RBAC, persistent JWT, audit logging, Redis cache,
async simulation, ML anomaly detection, TAXII sync, Sigma rules upload.
"""

import asyncio
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from slowapi.errors import RateLimitExceeded

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cybertwin")

# Phase 5 - Observability: opt-in JSON logging via ENABLE_JSON_LOGS=1
from backend.observability.logging_setup import auto_configure as _setup_logs
_setup_logs()

# Singletons + helpers shared across routers (see backend/api/deps.py)
from backend.api.deps import (  # noqa: E402
    PROJECT_ROOT,
    _client_ip,
    _get_cached_result,
    _safe_path,
    limiter,
    orchestrator as _orchestrator,
)

from backend.orchestrator import SimulationOrchestrator
from backend.database import init_db, save_run
from backend.auth import has_permission, require_permission
from backend.audit import init_audit_table, log_action
from backend.cache import cache

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: replaces deprecated @app.on_event handlers."""
    logger.info("CyberTwin SOC API v%s starting...", os.getenv("APP_VERSION", "3.0"))
    logger.info("Cache backend: %s", cache.backend)
    # Production safety: refuse to start with default credentials
    from backend.auth import check_production_safety
    check_production_safety()
    _orchestrator.initialise()
    logger.info("Orchestrator ready \u2014 %d scenarios loaded",
                len(_orchestrator.attack_engine._scenarios))
    # Phase 3 - SOC tables (alert feedback, cases, suppressions)
    from backend.soc import init_soc_tables
    init_soc_tables()
    logger.info("SOC tables ready (feedback, cases, suppressions)")
    yield
    logger.info("CyberTwin SOC API shutting down...")


app = FastAPI(
    title="CyberTwin SOC API",
    description="Enterprise Digital Twin platform for cyber attack simulation, detection validation, and SOC readiness.",
    version=os.getenv("APP_VERSION", "3.0.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3001").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Phase 5 - request_id correlation + Prometheus request duration
from backend.observability.middleware import RequestIdMiddleware
from backend.observability.metrics import MetricsMiddleware
from backend.observability.security_headers import SecurityHeadersMiddleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(RequestIdMiddleware)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})


init_db()
init_audit_table()


# ---------------------------------------------------------------------------
# Domain routers (progressive split of the legacy monolithic main.py)
# ---------------------------------------------------------------------------

from backend.api.routes import (  # noqa: E402
    auth as auth_routes,
    environment as environment_routes,
    health as health_routes,
    history as history_routes,
)

app.include_router(health_routes.router)
app.include_router(auth_routes.router)
app.include_router(environment_routes.router)
app.include_router(history_routes.router)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

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


class CustomScenarioRequest(BaseModel):
    id: Optional[str] = None
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=4000)
    severity: str = "medium"
    category: str = Field(default="custom", max_length=80)
    phases: list = Field(default_factory=list, max_length=50)

    @field_validator("id", mode="before")
    @classmethod
    def _sanitise_id(cls, v):
        if v is None:
            return v
        sanitised = re.sub(r"[^a-zA-Z0-9\-_]", "", str(v))[:64]
        if not sanitised:
            raise ValueError("Invalid scenario id")
        return sanitised

    @field_validator("severity")
    @classmethod
    def _severity_valid(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
#
# Domain-grouped endpoints live under ``backend.api.routes.*`` and are
# included near the bottom of this file. The remaining endpoints below are
# being progressively migrated.

# ---- Scenarios -----------------------------------------------------------

@app.get("/api/scenarios")
@limiter.limit("60/minute")
def list_scenarios(request: Request):
    return _orchestrator.attack_engine.list_scenarios()


@app.get("/api/scenarios/{scenario_id}")
@limiter.limit("60/minute")
def get_scenario(request: Request, scenario_id: str):
    scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario


@app.post("/api/scenarios/custom")
@limiter.limit("10/minute")
def save_custom_scenario(
    request: Request,
    scenario: CustomScenarioRequest,
    user=Depends(require_permission("manage_scenarios")),
):
    """Save a validated custom scenario. Requires analyst or admin role."""
    custom_dir = PROJECT_ROOT / "scenarios" / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    sid = scenario.id or f"sc-custom-{len(list(custom_dir.glob('*.json'))) + 1:03d}"
    filepath = _safe_path(custom_dir, sid, ".json")
    data = scenario.model_dump()
    data["id"] = sid
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    _orchestrator.attack_engine.load_scenarios()
    log_action("CREATE_SCENARIO", username=user["sub"], role=user.get("role"), resource=sid, ip_address=_client_ip(request))
    return {"status": "saved", "id": sid}


# ---- Simulation ----------------------------------------------------------

@app.post("/api/simulate", response_model=SimulationSummary)
@limiter.limit("10/minute")
async def run_simulation(
    request: Request,
    req: SimulationRequest,
    user=Depends(require_permission("run_simulation")),
):
    scenario = _orchestrator.attack_engine.get_scenario(req.scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{req.scenario_id}' not found")

    log_action("RUN_SIMULATION", username=user["sub"], role=user.get("role"), resource=req.scenario_id, ip_address=_client_ip(request))

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
    logger.info("Simulation complete: %s score=%.1f", req.scenario_id, scores["overall_score"])
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


# ---- WebSocket Live Simulation -------------------------------------------

def _websocket_bearer_token(websocket: WebSocket, query_token: str | None) -> tuple[str | None, bool]:
    """Extract a bearer token from WebSocket subprotocols or legacy query.

    Browsers cannot set an Authorization header for WebSockets. The frontend
    sends ["bearer", token] as Sec-WebSocket-Protocol so the JWT does not end
    up in URLs, browser history, or common proxy access logs. Query token
    support remains only for backward compatibility with older clients.
    """
    protocols = [
        item.strip()
        for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if item.strip()
    ]
    if len(protocols) >= 2 and protocols[0].lower() == "bearer":
        return protocols[1], True
    return query_token, False


@app.websocket("/ws/simulate/{scenario_id}")
async def ws_simulate(websocket: WebSocket, scenario_id: str, token: str | None = None):
    """Stream simulation events in real-time via WebSocket."""
    from backend.auth import JWT_SECRET, JWT_ALGORITHM
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
    if not has_permission(ws_user.get("role", "viewer"), "run_simulation"):
        await websocket.close(code=4003, reason="Permission 'run_simulation' required")
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
        log_action("RUN_SIMULATION_WS", username=ws_user.get("sub", "?"), role=ws_user.get("role", "?"), resource=scenario_id)

        try:
            save_run(scenario_id, scenario.get("name", ""), result)
        except Exception as exc:
            logger.warning("DB save failed for WebSocket run %s: %s", scenario_id, exc)

        logs = result.get("logs", [])
        timeline = result.get("timeline", [])
        alerts = result.get("alerts", [])
        phases = scenario.get("phases", [])

        # Use timeline if available, fall back to logs
        events = timeline if timeline else logs

        # --- Stream: start ---
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

        # --- Stream: events one-by-one with dramatic pacing ---
        alert_idx = 0
        current_phase = 0
        for i, event in enumerate(events):
            progress = round((i + 1) / len(events) * 100, 1)

            # Check phase transitions
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

            # Send the event
            await websocket.send_json({
                "type": "event",
                "data": event,
                "index": i,
                "total": len(events),
                "progress": progress,
                "phase": current_phase,
            })

            # Interleave alerts at the right proportion
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

            # Dramatic pacing: slower for malicious, fast for benign
            if event.get("is_malicious"):
                await asyncio.sleep(0.12)
            else:
                if i % 3 == 0:
                    await asyncio.sleep(0.02)

        # --- Stream: remaining alerts ---
        for alert in alerts[alert_idx:]:
            await websocket.send_json({
                "type": "alert",
                "data": alert,
                "alert_index": alert_idx,
                "total_alerts": len(alerts),
            })
            alert_idx += 1
            await asyncio.sleep(0.15)

        # --- Stream: incidents ---
        await asyncio.sleep(0.3)
        for inc in result.get("incidents", []):
            await websocket.send_json({"type": "incident", "data": inc})
            await asyncio.sleep(0.2)

        # --- Stream: scores ---
        await asyncio.sleep(0.5)
        await websocket.send_json({"type": "scores", "data": result["scores"]})

        # --- Stream: AI analysis summary ---
        await asyncio.sleep(0.3)
        if result.get("ai_analysis"):
            await websocket.send_json({
                "type": "ai_analysis",
                "data": {
                    "executive_narrative": result["ai_analysis"].get("executive_narrative", ""),
                    "severity_assessment": result["ai_analysis"].get("severity_assessment", ""),
                },
            })

        # --- Stream: complete with full result ---
        await asyncio.sleep(0.5)
        await websocket.send_json({"type": "complete", "data": result})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception as exc:
            logger.debug("Could not send WebSocket error frame: %s", exc)


# ---- Results (cache-backed) -----------------------------------------------

@app.get("/api/results/{scenario_id}")
@limiter.limit("60/minute")
def get_full_results(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)


@app.get("/api/results/{scenario_id}/alerts")
@limiter.limit("60/minute")
def get_alerts(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["alerts"]


@app.get("/api/results/{scenario_id}/incidents")
@limiter.limit("60/minute")
def get_incidents(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["incidents"]


@app.get("/api/results/{scenario_id}/timeline")
@limiter.limit("60/minute")
def get_timeline(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["timeline"]


@app.get("/api/results/{scenario_id}/scores")
@limiter.limit("60/minute")
def get_scores(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    result = cache.get(f"result:{scenario_id}")
    if result is None:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return result["scores"]


@app.get("/api/results/{scenario_id}/mitre")
@limiter.limit("60/minute")
def get_mitre_coverage(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["mitre_coverage"]


@app.get("/api/results/{scenario_id}/report")
@limiter.limit("60/minute")
def get_report(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["report"]


@app.get("/api/results/{scenario_id}/logs")
@limiter.limit("60/minute")
def get_logs(request: Request, scenario_id: str, limit: int = 200, offset: int = 0, user=Depends(require_permission("view_results"))):
    logs = _get_cached_result(scenario_id)["logs"]
    return {"total": len(logs), "offset": offset, "limit": limit, "data": logs[offset: offset + limit]}


@app.get("/api/results/{scenario_id}/ai-analysis")
@limiter.limit("60/minute")
def get_ai_analysis(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    result = _get_cached_result(scenario_id)
    ai = result.get("ai_analysis")
    if ai is None:
        raise HTTPException(404, "AI analysis not available.")
    return ai


@app.get("/api/results/{scenario_id}/statistics")
@limiter.limit("60/minute")
def get_statistics(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["logs_statistics"]


@app.get("/api/results/{scenario_id}/benchmark")
@limiter.limit("30/minute")
def get_benchmark(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    """Return NIST CSF v1.1 and CIS Controls v8 benchmark ratings for this simulation."""
    from backend.scoring import ScoringEngine
    result = _get_cached_result(scenario_id)
    engine = ScoringEngine()
    scores = result["scores"]
    return {
        "scenario_id": scenario_id,
        "nist_csf": engine.nist_csf_benchmark(scores),
        "cis_controls": engine.cis_controls_benchmark(scores),
    }


@app.get("/api/results/{scenario_id}/anomalies")
@limiter.limit("30/minute")
def get_anomalies(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    """Run ML anomaly detection on the cached simulation logs."""
    from backend.detection.anomaly import AnomalyDetector
    result = _get_cached_result(scenario_id)
    detector = AnomalyDetector()
    anomalies = detector.detect(result["logs"])
    return {"total": len(anomalies), "anomalies": anomalies}


# ---- MITRE Reference Data ------------------------------------------------

@app.get("/api/threat-intel")
@limiter.limit("60/minute")
def get_threat_intel(request: Request):
    """Aggregate all IOCs from all scenarios."""
    intel = {
        "threat_actors": [],
        "iocs": {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "urls": [],
            "email_addresses": [],
            "cves": [],
            "tools": [],
        },
        "references": [],
    }
    for sid, scenario in _orchestrator.attack_engine._scenarios.items():
        # Extract threat actor info
        if "threat_actor" in scenario:
            intel["threat_actors"].append(scenario["threat_actor"])
        # Extract references
        if "references" in scenario:
            intel["references"].extend(scenario["references"])
        # Extract IOCs from phases
        for phase in scenario.get("phases", []):
            ioc = phase.get("ioc", phase.get("iocs", {}))
            if isinstance(ioc, dict):
                for key in ["ip_addresses", "ips", "external_ips"]:
                    intel["iocs"]["ip_addresses"].extend(ioc.get(key, []))
                for key in ["domains", "domain"]:
                    intel["iocs"]["domains"].extend(ioc.get(key, []))
                for key in ["file_hashes", "hashes", "sha256"]:
                    val = ioc.get(key, {})
                    if isinstance(val, dict):
                        intel["iocs"]["file_hashes"].extend(val.values())
                    elif isinstance(val, list):
                        intel["iocs"]["file_hashes"].extend(val)
                for key in ["urls", "url"]:
                    intel["iocs"]["urls"].extend(ioc.get(key, []))
                for key in ["cves", "cve"]:
                    intel["iocs"]["cves"].extend(ioc.get(key, []))
                for key in ["tools", "tool"]:
                    intel["iocs"]["tools"].extend(ioc.get(key, []))
            # Also check indicators for additional IOCs
            indicators = phase.get("indicators", {})
            if isinstance(indicators, dict):
                for key in ["cve"]:
                    v = indicators.get(key)
                    if v:
                        intel["iocs"]["cves"].append(v) if isinstance(v, str) else intel["iocs"]["cves"].extend(v)
                for key in ["tools", "tool"]:
                    v = indicators.get(key)
                    if v:
                        if isinstance(v, list):
                            intel["iocs"]["tools"].extend(v)
                        elif isinstance(v, str):
                            intel["iocs"]["tools"].append(v)
                for key in ["url"]:
                    v = indicators.get(key)
                    if v and isinstance(v, str):
                        intel["iocs"]["urls"].append(v)
                for key in ["sender"]:
                    v = indicators.get(key)
                    if v and isinstance(v, str):
                        intel["iocs"]["email_addresses"].append(v)
    # Deduplicate
    for key in intel["iocs"]:
        intel["iocs"][key] = list(set(intel["iocs"][key]))
    intel["references"] = list(set(str(r) for r in intel["references"]))
    return intel


@app.get("/api/mitre/tactics")
@limiter.limit("60/minute")
def get_mitre_tactics(request: Request):
    from backend.mitre.attack_data import MITRE_TACTICS
    return dict(MITRE_TACTICS)


@app.get("/api/mitre/techniques")
@limiter.limit("60/minute")
def get_mitre_techniques(request: Request):
    from backend.mitre.attack_data import MITRE_TECHNIQUES
    return MITRE_TECHNIQUES


@app.get("/api/mitre/gap-analysis/{scenario_id}")
@limiter.limit("30/minute")
def mitre_gap_analysis(request: Request, scenario_id: str, user=Depends(require_permission("view_results"))):
    """Return full MITRE ATT&CK gap analysis: covered vs uncovered tactics and techniques."""
    from backend.mitre.attack_data import MITRE_TACTICS, MITRE_TECHNIQUES
    result = _get_cached_result(scenario_id)
    detected_tids = {a.get("technique_id", "") for a in result.get("alerts", [])}
    gap: dict = {"covered": [], "uncovered": [], "coverage_pct": 0.0, "by_tactic": {}}
    for tid, tech in MITRE_TECHNIQUES.items():
        tactic_id = tech.get("tactic", "")
        tactic_name = MITRE_TACTICS.get(tactic_id, {}).get("name", tactic_id)
        entry = {"technique_id": tid, "technique_name": tech["name"], "tactic": tactic_name}
        if any(tid == d or d.startswith(tid + ".") or tid.startswith(d + ".") for d in detected_tids):
            gap["covered"].append(entry)
        else:
            gap["uncovered"].append(entry)
        gap["by_tactic"].setdefault(tactic_name, {"covered": 0, "total": 0})
        gap["by_tactic"][tactic_name]["total"] += 1
        if entry in gap["covered"]:
            gap["by_tactic"][tactic_name]["covered"] += 1
    total = len(MITRE_TECHNIQUES)
    gap["coverage_pct"] = round(len(gap["covered"]) / total * 100, 1) if total else 0.0
    return gap


_MAX_SIGMA_BYTES = 256 * 1024  # 256 KB


@app.post("/api/sigma/upload")
@limiter.limit("10/minute")
async def upload_sigma_rule(request: Request, user=Depends(require_permission("manage_scenarios"))):
    """Upload a YAML Sigma rule and register it in the detection engine."""
    from backend.detection.sigma_loader import SigmaLoader
    body = await request.body()
    if len(body) > _MAX_SIGMA_BYTES:
        raise HTTPException(413, f"Sigma rule too large (>{_MAX_SIGMA_BYTES} bytes)")
    try:
        rule = SigmaLoader.load_from_yaml(body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, f"Invalid Sigma rule: {exc}")
    sigma_dir = PROJECT_ROOT / "data" / "sigma_rules"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    # _safe_path validates rule_id matches an identifier pattern AND the
    # resolved path stays inside sigma_dir.
    rule_file = _safe_path(sigma_dir, rule.rule_id, ".yml")
    rule_file.write_bytes(body)
    log_action("UPLOAD_SIGMA_RULE", username=user["sub"], role=user.get("role"), resource=rule.rule_id, ip_address=_client_ip(request))
    return {"status": "registered", "rule_id": rule.rule_id, "name": rule.name, "severity": rule.severity}


@app.get("/api/sigma/rules")
@limiter.limit("30/minute")
def list_sigma_rules(request: Request, user=Depends(require_permission("view_results"))):
    """List all uploaded Sigma rules."""
    sigma_dir = PROJECT_ROOT / "data" / "sigma_rules"
    if not sigma_dir.exists():
        return []
    rules = []
    for f in sigma_dir.glob("*.yml"):
        rules.append({"filename": f.name, "rule_id": f.stem, "size": f.stat().st_size})
    return rules


# ---- Detection Coverage Center (Phase 2) ---------------------------------
#
# These endpoints expose the *honest* MITRE ATT&CK detection coverage
# computed by joining: catalog + rules + scenarios + recent simulations.
# Results are cached for 30 seconds because the catalog has 622 techniques.

_COVERAGE_CACHE_KEY = "coverage:snapshot"
_COVERAGE_CACHE_TTL = 30  # seconds


def _compute_coverage_snapshot() -> dict[str, Any]:
    """Compute or return the cached coverage snapshot."""
    cached = cache.get(_COVERAGE_CACHE_KEY)
    if isinstance(cached, dict):
        return cached
    from backend.coverage.calculator import build_default_calculator
    calc = build_default_calculator()
    records, summary = calc.compute()
    snapshot = {
        "summary": summary.to_dict(),
        "records": [r.to_dict() for r in records],
    }
    try:
        cache.set(_COVERAGE_CACHE_KEY, snapshot, ttl=_COVERAGE_CACHE_TTL)
    except Exception as exc:
        logger.debug("Coverage cache write failed: %s", exc)
    return snapshot


@app.get("/api/coverage/summary")
@limiter.limit("60/minute")
def coverage_summary(request: Request, user=Depends(require_permission("view_results"))):
    """Aggregate detection-coverage figures for the whole MITRE catalog."""
    snap = _compute_coverage_snapshot()
    return snap["summary"]


@app.get("/api/coverage/mitre")
@limiter.limit("30/minute")
def coverage_mitre_table(
    request: Request,
    status: Optional[str] = None,
    tactic: Optional[str] = None,
    user=Depends(require_permission("view_results")),
):
    """Full per-technique coverage table.

    Optional query filters:
      - status:  not_covered | rule_exists | rule_exists_untested |
                 tested_and_detected | tested_but_failed | noisy |
                 needs_data_source | not_applicable
      - tactic:  TA0001..TA0043
    """
    snap = _compute_coverage_snapshot()
    records = snap["records"]
    if status:
        records = [r for r in records if r["status"] == status]
    if tactic:
        records = [r for r in records if r["tactic_id"] == tactic]
    return {"total": len(records), "records": records}


@app.get("/api/coverage/technique/{technique_id}")
@limiter.limit("60/minute")
def coverage_technique_detail(
    request: Request,
    technique_id: str,
    user=Depends(require_permission("view_results")),
):
    """Full coverage record for one technique."""
    snap = _compute_coverage_snapshot()
    for r in snap["records"]:
        if r["technique_id"] == technique_id:
            return r
    raise HTTPException(404, f"Technique '{technique_id}' not found in catalog")


@app.get("/api/coverage/gaps")
@limiter.limit("30/minute")
def coverage_gaps(
    request: Request,
    high_risk_only: bool = False,
    limit: int = 50,
    user=Depends(require_permission("view_results")),
):
    """Top actionable detection gaps with recommendations."""
    snap = _compute_coverage_snapshot()
    from backend.coverage.calculator import CoverageCalculator  # noqa: F401
    from backend.coverage.gap_analyzer import GapAnalyzer
    from backend.coverage.models import TechniqueCoverage, TechniqueStatus

    # Rebuild typed records from the cached dicts to feed the analyzer.
    typed_records = []
    for r in snap["records"]:
        typed_records.append(TechniqueCoverage(
            technique_id=r["technique_id"],
            name=r["name"],
            tactic_id=r["tactic_id"],
            tactic_name=r["tactic_name"],
            is_subtechnique=r["is_subtechnique"],
            rules=list(r.get("rules", [])),
            rule_count=r.get("rule_count", 0),
            scenarios=list(r.get("scenarios", [])),
            scenario_count=r.get("scenario_count", 0),
            last_simulation_id=r.get("last_simulation_id"),
            last_simulation_at=r.get("last_simulation_at"),
            last_simulation_detected=r.get("last_simulation_detected"),
            confidence=r.get("confidence", 0.0),
            required_logs=list(r.get("required_logs", [])),
            available_logs=list(r.get("available_logs", [])),
            missing_logs=list(r.get("missing_logs", [])),
            status=TechniqueStatus(r["status"]),
        ))

    gaps = GapAnalyzer(typed_records).analyse(only_high_risk=high_risk_only)
    gaps = gaps[: max(1, min(limit, 500))]
    return {"total": len(gaps), "gaps": [g.to_dict() for g in gaps]}


@app.get("/api/coverage/gaps/high-risk")
@limiter.limit("30/minute")
def coverage_high_risk_gaps(request: Request, limit: int = 25,
                            user=Depends(require_permission("view_results"))):
    """Shortcut to the highest-priority gaps only."""
    return coverage_gaps(
        request=request, high_risk_only=True, limit=limit, user=user
    )


@app.post("/api/coverage/recalculate")
@limiter.limit("10/minute")
def coverage_recalculate(
    request: Request,
    user=Depends(require_permission("configure_system")),
):
    """Force a fresh coverage computation, bypassing the 30s cache."""
    cache.delete(_COVERAGE_CACHE_KEY) if hasattr(cache, "delete") else None
    snap = _compute_coverage_snapshot()
    log_action("COVERAGE_RECALCULATE", username=user["sub"], role=user.get("role"),
               ip_address=_client_ip(request),
               details={"catalog_total": snap["summary"]["catalog_total"]})
    return {"status": "recalculated", "summary": snap["summary"]}


# ---- SOC Workflow (Phase 3): Alert Feedback, Cases, Suppressions ---------

class FeedbackRequest(BaseModel):
    rule_id: str = Field(min_length=1, max_length=120)
    verdict: str
    reason: str = Field(default="", max_length=2000)

    @field_validator("verdict")
    @classmethod
    def _verdict_valid(cls, v):
        from backend.soc.models import AlertVerdict
        if v not in {a.value for a in AlertVerdict}:
            raise ValueError(f"verdict must be one of {[a.value for a in AlertVerdict]}")
        return v


class CaseCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    severity: str = "medium"
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    incident_ids: list[str] = Field(default_factory=list, max_length=100)
    affected_hosts: list[str] = Field(default_factory=list, max_length=100)
    affected_users: list[str] = Field(default_factory=list, max_length=100)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=50)
    assignee: Optional[str] = Field(default=None, max_length=120)

    @field_validator("severity")
    @classmethod
    def _case_severity_valid(cls, v: str) -> str:
        from backend.soc.models import CaseSeverity
        if v not in {s.value for s in CaseSeverity}:
            raise ValueError(f"severity must be one of {[s.value for s in CaseSeverity]}")
        return v

    @field_validator("alert_ids", "incident_ids", "affected_hosts", "affected_users", "mitre_techniques", "tags")
    @classmethod
    def _case_list_items_bounded(cls, v: list[str]) -> list[str]:
        if any(len(str(item)) > 160 for item in v):
            raise ValueError("list item exceeds 160 characters")
        return v


class CasePatchRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    severity: Optional[str] = None
    status: Optional[str] = None
    assignee: Optional[str] = Field(default=None, max_length=120)
    tags: Optional[list[str]] = Field(default=None, max_length=50)

    @field_validator("severity")
    @classmethod
    def _patch_severity_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from backend.soc.models import CaseSeverity
        if v not in {s.value for s in CaseSeverity}:
            raise ValueError(f"severity must be one of {[s.value for s in CaseSeverity]}")
        return v

    @field_validator("status")
    @classmethod
    def _patch_status_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        from backend.soc.models import CaseStatus
        if v not in {s.value for s in CaseStatus}:
            raise ValueError(f"status must be one of {[s.value for s in CaseStatus]}")
        return v


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class EvidenceRequest(BaseModel):
    type: str = Field(default="alert", max_length=40)
    reference: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=3000)
    payload: Optional[dict[str, Any]] = None

    @field_validator("type")
    @classmethod
    def _evidence_type_valid(cls, v: str) -> str:
        allowed = {"alert", "event", "ioc", "file", "url", "note"}
        if v not in allowed:
            raise ValueError(f"type must be one of {sorted(allowed)}")
        return v

    @field_validator("payload")
    @classmethod
    def _payload_size_cap(cls, v: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if v is not None and _approx_size(v) > 64 * 1024:
            raise ValueError("payload exceeds 64 KB cap")
        return v


class CaseCloseRequest(BaseModel):
    closure_reason: str = Field(min_length=5, max_length=3000)
    final_status: str = "closed"

    @field_validator("final_status")
    @classmethod
    def _final_status_valid(cls, v: str) -> str:
        allowed = {"closed", "resolved", "false_positive"}
        if v not in allowed:
            raise ValueError(f"final_status must be one of {sorted(allowed)}")
        return v


class AssignRequest(BaseModel):
    assignee: str = Field(min_length=1, max_length=120)


class SuppressionRequest(BaseModel):
    scope: str
    target: str = Field(min_length=1, max_length=250)
    reason: str = Field(min_length=5, max_length=2000)
    duration_hours: Optional[int] = Field(default=None, ge=1, le=24 * 90)
    expires_at: Optional[str] = Field(default=None, max_length=80)
    approved_by: Optional[str] = Field(default=None, max_length=120)

    @field_validator("scope")
    @classmethod
    def _suppression_scope_valid(cls, v: str) -> str:
        from backend.soc.models import SuppressionScope
        if v not in {s.value for s in SuppressionScope}:
            raise ValueError(f"scope must be one of {[s.value for s in SuppressionScope]}")
        return v


# ---- Alert feedback ------------------------------------------------------

@app.post("/api/alerts/{alert_id}/feedback")
@limiter.limit("60/minute")
def post_alert_feedback(
    alert_id: str, payload: FeedbackRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    """Record analyst verdict on an alert (TP/FP/Benign/Duplicate/...)."""
    from backend.soc import record_feedback
    try:
        fb = record_feedback(
            alert_id=alert_id, rule_id=payload.rule_id,
            verdict=payload.verdict, reason=payload.reason,
            analyst=user["sub"], role=user.get("role", "viewer"),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("ALERT_FEEDBACK", username=user["sub"], role=user.get("role"),
               resource=alert_id, ip_address=_client_ip(request),
               details={"rule_id": payload.rule_id, "verdict": payload.verdict})
    return fb.to_dict()


@app.get("/api/alerts/feedback/summary")
@limiter.limit("60/minute")
def get_feedback_summary(request: Request,
                         user=Depends(require_permission("view_results"))):
    from backend.soc import feedback_summary
    return feedback_summary()


@app.get("/api/alerts/feedback/noisy-rules")
@limiter.limit("30/minute")
def get_noisy_rules(
    request: Request, min_total: int = 3, threshold: float = 0.5,
    user=Depends(require_permission("view_results")),
):
    """Return rules with high false-positive feedback rates."""
    from backend.soc import list_noisy_rules
    return {"rules": list_noisy_rules(min_total=min_total, fp_threshold=threshold)}


# ---- Cases ---------------------------------------------------------------

@app.post("/api/cases")
@limiter.limit("30/minute")
def post_case(
    payload: CaseCreateRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import create_case
    try:
        case = create_case(
            title=payload.title, description=payload.description,
            severity=payload.severity, created_by=user["sub"],
            alert_ids=payload.alert_ids, incident_ids=payload.incident_ids,
            affected_hosts=payload.affected_hosts,
            affected_users=payload.affected_users,
            mitre_techniques=payload.mitre_techniques,
            tags=payload.tags, assignee=payload.assignee,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("CASE_CREATE", username=user["sub"], role=user.get("role"),
               resource=case.case_id, ip_address=_client_ip(request),
               details={"severity": case.severity})
    return case.to_dict()


@app.get("/api/cases")
@limiter.limit("60/minute")
def list_cases_endpoint(
    request: Request,
    status: Optional[str] = None, severity: Optional[str] = None,
    assignee: Optional[str] = None, limit: int = 50,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import list_cases
    cases = list_cases(status=status, severity=severity,
                       assignee=assignee, limit=limit)
    return {"total": len(cases), "cases": [c.to_dict() for c in cases]}


@app.get("/api/cases/{case_id}")
@limiter.limit("60/minute")
def get_case_endpoint(case_id: str, request: Request,
                      user=Depends(require_permission("view_results"))):
    from backend.soc import get_case
    case = get_case(case_id)
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    return case.to_dict()


@app.patch("/api/cases/{case_id}")
@limiter.limit("60/minute")
def patch_case(
    case_id: str, payload: CasePatchRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import update_case
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    case = update_case(case_id, **fields)
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_UPDATE", username=user["sub"], role=user.get("role"),
               resource=case_id, ip_address=_client_ip(request),
               details={"changes": list(fields.keys())})
    return case.to_dict()


@app.post("/api/cases/{case_id}/comments")
@limiter.limit("60/minute")
def post_case_comment(
    case_id: str, payload: CommentRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import add_comment
    try:
        cmt = add_comment(case_id, author=user["sub"],
                          role=user.get("role", "viewer"), body=payload.body)
    except ValueError as exc:
        raise HTTPException(404 if "not found" in str(exc) else 400, str(exc))
    return cmt.to_dict()


@app.post("/api/cases/{case_id}/evidence")
@limiter.limit("60/minute")
def post_case_evidence(
    case_id: str, payload: EvidenceRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import add_evidence
    try:
        ev = add_evidence(case_id, type=payload.type, reference=payload.reference,
                          description=payload.description,
                          added_by=user["sub"], payload=payload.payload)
    except ValueError as exc:
        raise HTTPException(404 if "not found" in str(exc) else 400, str(exc))
    return ev.to_dict()


@app.post("/api/cases/{case_id}/assign")
@limiter.limit("30/minute")
def post_case_assign(
    case_id: str, payload: AssignRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import assign_case
    case = assign_case(case_id, assignee=payload.assignee)
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_ASSIGN", username=user["sub"], role=user.get("role"),
               resource=case_id, ip_address=_client_ip(request),
               details={"assignee": payload.assignee})
    return case.to_dict()


@app.post("/api/cases/{case_id}/close")
@limiter.limit("30/minute")
def post_case_close(
    case_id: str, payload: CaseCloseRequest, request: Request,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import close_case
    try:
        case = close_case(case_id, closure_reason=payload.closure_reason,
                          final_status=payload.final_status)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if case is None:
        raise HTTPException(404, f"Case '{case_id}' not found")
    log_action("CASE_CLOSE", username=user["sub"], role=user.get("role"),
               resource=case_id, ip_address=_client_ip(request),
               details={"final_status": payload.final_status})
    return case.to_dict()


# ---- Suppressions --------------------------------------------------------

@app.post("/api/suppressions")
@limiter.limit("20/minute")
def post_suppression(
    payload: SuppressionRequest, request: Request,
    user=Depends(require_permission("configure_system")),
):
    from backend.soc import create_suppression
    try:
        s = create_suppression(
            scope=payload.scope, target=payload.target,
            reason=payload.reason,
            duration_hours=payload.duration_hours,
            expires_at=payload.expires_at,
            created_by=user["sub"],
            approved_by=payload.approved_by,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_action("SUPPRESSION_CREATE", username=user["sub"], role=user.get("role"),
               ip_address=_client_ip(request),
               details={"scope": s.scope, "target": s.target,
                        "expires_at": s.expires_at})
    return s.to_dict()


@app.get("/api/suppressions")
@limiter.limit("60/minute")
def get_suppressions(
    request: Request, only_active: bool = True,
    user=Depends(require_permission("view_results")),
):
    from backend.soc import list_suppressions
    items = list_suppressions(only_active=only_active)
    return {"total": len(items), "suppressions": [s.to_dict() for s in items]}


@app.delete("/api/suppressions/{suppression_id}")
@limiter.limit("20/minute")
def delete_suppression_endpoint(
    suppression_id: int, request: Request,
    user=Depends(require_permission("configure_system")),
):
    from backend.soc import delete_suppression
    if not delete_suppression(suppression_id, deleted_by=user["sub"]):
        raise HTTPException(404, f"Suppression #{suppression_id} not found")
    log_action("SUPPRESSION_DELETE", username=user["sub"],
               role=user.get("role"), resource=str(suppression_id),
               ip_address=_client_ip(request))
    return {"status": "deleted", "suppression_id": suppression_id}


# ---- Enterprise Connectors registry (Phase 5) ----------------------------

@app.get("/api/connectors")
@limiter.limit("60/minute")
def list_enterprise_connectors(request: Request,
                               user=Depends(require_permission("view_results"))):
    """Catalog of registered SIEM/SOAR/EDR/ITSM/TI connectors."""
    from backend.connectors import list_connectors
    return {"connectors": list_connectors()}


@app.get("/api/connectors/{kind}/{name}/check")
@limiter.limit("30/minute")
def check_enterprise_connector(kind: str, name: str, request: Request,
                               user=Depends(require_permission("view_results"))):
    """Run check_connection() against a registered connector. Stubs return 501."""
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


# ---- Live Log Ingestion (Phase 4) ----------------------------------------

# Hard caps. Total batch payload is bounded by event_count * per_event_size
# AND by the global request body limit enforced at the ASGI layer (uvicorn
# default is 1 MB but we set a deliberate 16 MB cap for ingestion).
_INGEST_MAX_EVENTS = 5000
_INGEST_MAX_EVENT_BYTES = 64 * 1024          # 64 KB per event (generous for OCSF)
_INGEST_MAX_SYSLOG_LINES = 5000
_INGEST_MAX_SYSLOG_LINE_LEN = 8 * 1024       # RFC 5424 says SHOULD support 2048


def _approx_size(obj: Any) -> int:
    """Cheap upper bound on the JSON-serialised size of a dict."""
    try:
        return len(json.dumps(obj, default=str))
    except Exception:
        return _INGEST_MAX_EVENT_BYTES + 1   # treat as oversize on error


class IngestEventRequest(BaseModel):
    event: dict[str, Any]
    source_type: Optional[str] = None
    tenant_id: Optional[str] = None

    @field_validator("event")
    @classmethod
    def _event_size_cap(cls, v):
        if _approx_size(v) > _INGEST_MAX_EVENT_BYTES:
            raise ValueError(
                f"Event exceeds {_INGEST_MAX_EVENT_BYTES // 1024} KB cap."
            )
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
        # Block the multiplied-DoS angle: 5000 × 100 KB == 500 MB.
        for i, evt in enumerate(v):
            if _approx_size(evt) > _INGEST_MAX_EVENT_BYTES:
                raise ValueError(
                    f"Event #{i} exceeds "
                    f"{_INGEST_MAX_EVENT_BYTES // 1024} KB cap."
                )
        return v


class IngestSyslogRequest(BaseModel):
    lines: list[str]
    tenant_id: Optional[str] = None

    @field_validator("lines")
    @classmethod
    def _lines_size_cap(cls, v):
        if len(v) > _INGEST_MAX_SYSLOG_LINES:
            raise ValueError(
                f"Syslog batch capped at {_INGEST_MAX_SYSLOG_LINES} lines."
            )
        for i, line in enumerate(v):
            if len(line) > _INGEST_MAX_SYSLOG_LINE_LEN:
                raise ValueError(
                    f"Line #{i} exceeds "
                    f"{_INGEST_MAX_SYSLOG_LINE_LEN // 1024} KB cap."
                )
        return v


@app.post("/api/ingest/event")
@limiter.limit("600/minute")
def ingest_event(payload: IngestEventRequest, request: Request,
                 user=Depends(require_permission("run_simulation"))):
    """Submit one event for normalisation + buffering."""
    from backend.ingestion import get_pipeline
    try:
        ocsf = get_pipeline().ingest_one(
            payload.event, source_type=payload.source_type,
            tenant_id=payload.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"status": "accepted", "event": ocsf}


@app.post("/api/ingest/batch")
@limiter.limit("60/minute")
def ingest_batch(payload: IngestBatchRequest, request: Request,
                 user=Depends(require_permission("run_simulation"))):
    """Submit a batch of events (capped at 5000)."""
    from backend.ingestion import get_pipeline
    return get_pipeline().ingest_batch(
        payload.events, source_type=payload.source_type,
        tenant_id=payload.tenant_id,
    )


@app.post("/api/ingest/syslog")
@limiter.limit("60/minute")
def ingest_syslog(payload: IngestSyslogRequest, request: Request,
                  user=Depends(require_permission("run_simulation"))):
    """Ingest raw RFC 3164 / 5424 syslog text lines."""
    from backend.ingestion import get_pipeline
    return get_pipeline().ingest_syslog_lines(payload.lines, tenant_id=payload.tenant_id)


@app.post("/api/ingest/upload")
@limiter.limit("10/minute")
async def ingest_upload(request: Request,
                        user=Depends(require_permission("run_simulation"))):
    """Accept a newline-delimited JSON file (NDJSON) upload."""
    body = await request.body()
    if not body:
        raise HTTPException(400, "Empty body")
    if len(body) > 25 * 1024 * 1024:  # 25 MB max
        raise HTTPException(413, "File too large (max 25 MB)")
    from backend.ingestion import get_pipeline
    pipeline = get_pipeline()
    accepted = rejected = 0
    for line in body.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
            pipeline.ingest_one(evt)
            accepted += 1
        except Exception:
            rejected += 1
    log_action("INGEST_UPLOAD", username=user["sub"], role=user.get("role"),
               ip_address=_client_ip(request),
               details={"accepted": accepted, "rejected": rejected})
    return {"accepted": accepted, "rejected": rejected}


@app.get("/api/ingest/stats")
@limiter.limit("60/minute")
def ingest_stats(request: Request,
                 user=Depends(require_permission("view_results"))):
    """Counters: throughput, by source type, drops by reason."""
    from backend.ingestion import get_pipeline
    pipe = get_pipeline()
    return {**pipe.stats.to_dict(), "buffer_size": pipe.buffer_size()}


@app.get("/api/ingest/sources")
@limiter.limit("60/minute")
def ingest_supported_sources(request: Request,
                             user=Depends(require_permission("view_results"))):
    """List all source_type identifiers the normaliser knows about."""
    from backend.normalization import list_supported
    return {"supported": list_supported()}


@app.get("/api/ingest/health")
@limiter.limit("120/minute")
def ingest_health(request: Request):
    """Public health probe. Reports buffer size and event throughput."""
    from backend.ingestion import get_pipeline
    pipe = get_pipeline()
    return {
        "status": "ok",
        "buffer_size": pipe.buffer_size(),
        "events_total": pipe.stats.total_events_received,
        "alerts_total": pipe.stats.total_alerts_generated,
    }


@app.post("/api/ingest/detect")
@limiter.limit("10/minute")
def ingest_detect(request: Request,
                  user=Depends(require_permission("view_results"))):
    """Run the detection engine over the current buffer."""
    from backend.ingestion import get_pipeline
    return get_pipeline().detect()


@app.delete("/api/ingest/buffer")
@limiter.limit("10/minute")
def ingest_clear(request: Request,
                 user=Depends(require_permission("configure_system"))):
    """Empty the in-memory ingestion buffer (admin)."""
    from backend.ingestion import get_pipeline
    get_pipeline().clear()
    log_action("INGEST_CLEAR", username=user["sub"], role=user.get("role"),
               ip_address=_client_ip(request))
    return {"status": "cleared"}


# ---- Evidence-first AI Analysis (Phase 3) --------------------------------

@app.get("/api/results/{scenario_id}/ai-evidence")
@limiter.limit("30/minute")
def get_ai_evidence_analysis(
    request: Request, scenario_id: str,
    user=Depends(require_permission("view_results")),
):
    """Return the structured evidence-first AI analysis for a simulation.

    Unlike `/api/results/{id}/ai-analysis`, this endpoint enforces the
    Phase 3 schema: `summary`, `confidence`, `evidence[]`, `mitre[]`,
    `hypotheses[]`, `recommended_actions[]`, `iocs`, `limitations[]`,
    `guardrails[]` -- with PII/secrets masked.
    """
    result = _get_cached_result(scenario_id)
    from backend.ai_analyst import AIAnalyst
    return AIAnalyst().analyse_with_evidence(
        scenario=result.get("scenario", {}),
        alerts=result.get("alerts", []),
        incidents=result.get("incidents", []),
        scores=result.get("scores", {}),
        mitre_coverage=result.get("mitre_coverage", {}),
        timeline=result.get("timeline", []),
        logs_stats=result.get("logs_statistics", {}),
    )


# ---- SOAR Integration (TheHive + Cortex) ---------------------------------

@app.get("/api/soar/status")
@limiter.limit("30/minute")
def soar_status(request: Request, user=Depends(require_permission("view_results"))):
    """Check connectivity to TheHive and Cortex."""
    from backend.soar import TheHiveClient, CortexClient
    thehive = TheHiveClient().check_connection()
    cortex = CortexClient().check_connection()
    return {
        "thehive": thehive,
        "cortex": cortex,
        "soar_available": thehive["connected"] or cortex["connected"],
    }


@app.post("/api/soar/push/{result_id}")
@limiter.limit("10/minute")
async def push_to_thehive(
    result_id: str,
    request: Request,
    user=Depends(require_permission("run_simulation")),
):
    """Push a simulation result to TheHive as a new case with IOCs and tasks."""
    result = _get_cached_result(result_id)
    from backend.soar import TheHiveClient
    loop = asyncio.get_event_loop()
    try:
        push_result = await loop.run_in_executor(
            None, lambda: TheHiveClient().push_simulation_result(result)
        )
        log_action(
            "SOAR_PUSH", username=user["sub"], role=user.get("role"),
            resource=result_id, ip_address=_client_ip(request),
            details={"case_id": push_result.get("case_id")},
        )
        return push_result
    except Exception as exc:
        raise HTTPException(502, f"TheHive push failed: {exc}")


@app.post("/api/soar/analyze-iocs/{result_id}")
@limiter.limit("5/minute")
async def analyze_iocs_cortex(
    result_id: str,
    request: Request,
    user=Depends(require_permission("run_simulation")),
):
    """Submit IOCs from a simulation result to Cortex analyzers."""
    result = _get_cached_result(result_id)
    iocs = result.get("ai_analysis", {}).get("iocs", [])
    if not iocs:
        return {"message": "No IOCs found in this simulation result", "jobs": []}
    from backend.soar import CortexClient
    loop = asyncio.get_event_loop()
    try:
        jobs = await loop.run_in_executor(
            None, lambda: CortexClient().analyze_iocs(iocs)
        )
        log_action(
            "SOAR_CORTEX", username=user["sub"], role=user.get("role"),
            resource=result_id, ip_address=_client_ip(request),
            details={"iocs_submitted": len(jobs)},
        )
        return {"iocs_submitted": len(jobs), "jobs": jobs}
    except Exception as exc:
        raise HTTPException(502, f"Cortex analysis failed: {exc}")


@app.get("/api/soar/analyzers")
@limiter.limit("10/minute")
def list_cortex_analyzers(
    request: Request,
    data_type: Optional[str] = None,
    user=Depends(require_permission("view_results")),
):
    """List available Cortex analyzers, optionally filtered by data type."""
    from backend.soar import CortexClient
    return CortexClient().list_analyzers(data_type=data_type)


@app.post("/api/mitre/sync-taxii")
@limiter.limit("2/hour")
async def sync_mitre_taxii(request: Request, user=Depends(require_permission("configure_system"))):
    """Sync MITRE ATT&CK techniques from the official TAXII 2.1 feed."""
    from backend.mitre.taxii_sync import sync_from_taxii
    loop = asyncio.get_event_loop()
    try:
        count = await loop.run_in_executor(None, sync_from_taxii)
        log_action("TAXII_SYNC", username=user["sub"], role=user.get("role"), ip_address=_client_ip(request), details={"techniques_synced": count})
        return {"status": "synced", "techniques_updated": count}
    except Exception as exc:
        raise HTTPException(502, f"TAXII sync failed: {exc}")
