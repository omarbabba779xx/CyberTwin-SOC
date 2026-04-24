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
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cybertwin")

limiter = Limiter(key_func=get_remote_address)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.orchestrator import SimulationOrchestrator
from backend.database import init_db, save_run, get_runs, get_run, get_runs_by_scenario, delete_run, get_stats
from backend.auth import (
    authenticate_user, create_token, verify_token, verify_token_optional,
    require_permission,
)
from backend.audit import init_audit_table, log_action, get_audit_log
from backend.cache import cache

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberTwin SOC API",
    description="Enterprise Digital Twin platform for cyber attack simulation, detection validation, and SOC readiness.",
    version=os.getenv("APP_VERSION", "3.0.0"),
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3001").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc):
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})


_orchestrator = SimulationOrchestrator()
init_db()
init_audit_table()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class SimulationRequest(BaseModel):
    scenario_id: str
    duration_minutes: int = 60
    normal_intensity: str = "normal"


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
    name: str
    description: str = ""
    severity: str = "medium"
    category: str = "custom"
    phases: list = []

    @field_validator("id", mode="before")
    @classmethod
    def _sanitise_id(cls, v):
        if v is None:
            return v
        sanitised = re.sub(r"[^a-zA-Z0-9\-_]", "", str(v))[:64]
        if not sanitised:
            raise ValueError("Invalid scenario id")
        return sanitised


# ---------------------------------------------------------------------------
# Helper: get client IP
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    logger.info("CyberTwin SOC API v%s starting...", os.getenv("APP_VERSION", "3.0"))
    logger.info("Cache backend: %s", cache.backend)
    _orchestrator.initialise()
    logger.info("Orchestrator ready — %d scenarios loaded", len(_orchestrator.attack_engine._scenarios))


@app.get("/")
@limiter.limit("60/minute")
def root(request: Request):
    return {"name": "CyberTwin SOC API", "version": os.getenv("APP_VERSION", "3.0.0"), "status": "running", "cache": cache.backend}


@app.get("/api/health")
@limiter.limit("120/minute")
def health(request: Request):
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


# ---- Authentication ------------------------------------------------------

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, data: LoginRequest):
    ip = _client_ip(request)
    user = authenticate_user(data.username, data.password)
    if user is None:
        log_action("LOGIN", username=data.username, ip_address=ip, status="failure")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    from backend.auth import ROLES
    token = create_token(user["username"], user["role"])
    log_action("LOGIN", username=user["username"], role=user["role"], ip_address=ip)
    return {
        "token": token,
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "permissions": sorted(ROLES.get(user["role"], set())),
        "expires_in": int(os.getenv("JWT_EXPIRY_HOURS", "24")) * 3600,
    }


@app.get("/api/auth/me")
@limiter.limit("30/minute")
def get_me(request: Request, user=Depends(verify_token)):
    return {"username": user["sub"], "role": user.get("role", "viewer"), "permissions": user.get("permissions", [])}


# ---- Audit Log (admin only) -----------------------------------------------

@app.get("/api/audit")
@limiter.limit("30/minute")
def audit_log(request: Request, limit: int = 200, user=Depends(require_permission("view_audit_log"))):
    log_action("VIEW_AUDIT_LOG", username=user["sub"], role=user.get("role"), ip_address=_client_ip(request))
    return get_audit_log(limit=limit)


# ---- Environment ---------------------------------------------------------

@app.get("/api/environment")
@limiter.limit("60/minute")
def get_environment(request: Request):
    return _orchestrator.environment.to_dict()


@app.get("/api/environment/hosts")
@limiter.limit("60/minute")
def get_hosts(request: Request):
    return list(_orchestrator.environment.get_hosts().values())


@app.get("/api/environment/users")
@limiter.limit("60/minute")
def get_users(request: Request):
    return list(_orchestrator.environment.get_users().values())


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
    data = scenario.model_dump()
    data["id"] = sid
    filepath = custom_dir / f"{sid}.json"
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

@app.websocket("/ws/simulate/{scenario_id}")
async def ws_simulate(websocket: WebSocket, scenario_id: str, token: str | None = None):
    """Stream simulation events in real-time via WebSocket."""
    from backend.auth import JWT_SECRET, JWT_ALGORITHM
    import jwt as _jwt
    if token is None:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    try:
        ws_user = _jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (_jwt.ExpiredSignatureError, _jwt.InvalidTokenError):
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await websocket.accept()

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
        except Exception:
            pass

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
        except Exception:
            pass


# ---- Results (cache-backed) -----------------------------------------------

def _get_cached_result(scenario_id: str) -> dict:
    result = cache.get(f"result:{scenario_id}")
    if result is None:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return result


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


# ---- History (SQLite) ----------------------------------------------------

@app.get("/api/history")
@limiter.limit("60/minute")
def list_history(request: Request, limit: int = 50):
    return get_runs(limit)


@app.get("/api/history/stats")
@limiter.limit("60/minute")
def history_stats(request: Request):
    return get_stats()


@app.get("/api/history/{run_id}")
@limiter.limit("60/minute")
def history_detail(request: Request, run_id: int):
    run = get_run(run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@app.get("/api/history/scenario/{scenario_id}")
@limiter.limit("60/minute")
def history_by_scenario(request: Request, scenario_id: str):
    return get_runs_by_scenario(scenario_id)


@app.delete("/api/history/{run_id}")
@limiter.limit("30/minute")
def history_delete(request: Request, run_id: int, user=Depends(require_permission("delete_history"))):
    delete_run(run_id)
    log_action("DELETE_HISTORY", username=user["sub"], role=user.get("role"), resource=str(run_id), ip_address=_client_ip(request))
    return {"status": "deleted"}


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


@app.post("/api/sigma/upload")
@limiter.limit("10/minute")
async def upload_sigma_rule(request: Request, user=Depends(require_permission("manage_scenarios"))):
    """Upload a YAML Sigma rule and register it in the detection engine."""
    from backend.detection.sigma_loader import SigmaLoader
    body = await request.body()
    try:
        rule = SigmaLoader.load_from_yaml(body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, f"Invalid Sigma rule: {exc}")
    sigma_dir = PROJECT_ROOT / "data" / "sigma_rules"
    sigma_dir.mkdir(parents=True, exist_ok=True)
    rule_file = sigma_dir / f"{rule.rule_id}.yml"
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
