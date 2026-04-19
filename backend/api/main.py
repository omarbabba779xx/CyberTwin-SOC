"""
CyberTwin SOC - FastAPI Application

REST API + WebSocket that exposes the simulation platform to the frontend dashboard.
"""

import asyncio
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any

import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables
load_dotenv()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("cybertwin")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.orchestrator import SimulationOrchestrator
from backend.database import init_db, save_run, get_runs, get_run, get_runs_by_scenario, delete_run, get_stats

# ---------------------------------------------------------------------------
# JWT Authentication
# ---------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET") or secrets.token_hex(32)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
security = HTTPBearer(auto_error=False)


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "role": "analyst",
        "exp": datetime.utcnow() + timedelta(hours=24),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Optional auth - returns user info if token provided, None otherwise."""
    if credentials is None:
        return None
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberTwin SOC API",
    description="Digital Twin platform for cyber attack simulation, detection validation, and SOC readiness assessment.",
    version=os.getenv("APP_VERSION", "2.0.0"),
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

# Rate limiter setup
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    """Return a 429 response when rate limit is exceeded."""
    return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})


# Singleton orchestrator
_orchestrator = SimulationOrchestrator()

# Initialize database
init_db()

# Cache for last simulation result (per scenario)
_results_cache: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    """Initialize orchestrator and log startup information."""
    logger.info("CyberTwin SOC API v%s starting...", os.getenv("APP_VERSION", "2.0"))
    logger.info("CORS origins: %s", os.getenv("CORS_ORIGINS", "*"))
    _orchestrator.initialise()
    logger.info("Orchestrator initialized with %d scenarios", len(_orchestrator.attack_engine._scenarios))


@app.get("/")
@limiter.limit("60/minute")
def root(request: Request):
    """Return basic API status information."""
    return {"name": "CyberTwin SOC API", "version": os.getenv("APP_VERSION", "2.0.0"), "status": "running"}


@app.get("/api/health")
@limiter.limit("60/minute")
def health(request: Request):
    return {"status": "ok"}


# ---- Authentication ------------------------------------------------------

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, data: dict):
    """Simple login - accepts predefined users for demo purposes."""
    username = data.get("username", "analyst")
    password = data.get("password", "")
    logger.info("Login attempt: %s", username)
    # Load credentials from environment variables
    valid_users = {
        "admin": os.getenv("AUTH_ADMIN_PASSWORD", "cybertwin2024"),
        "analyst": os.getenv("AUTH_ANALYST_PASSWORD", "soc2024"),
        "viewer": os.getenv("AUTH_VIEWER_PASSWORD", "view2024"),
    }
    if username in valid_users and valid_users[username] == password:
        token = create_token(username)
        logger.info("Login successful: %s", username)
        return {"token": token, "username": username, "role": "analyst", "expires_in": 86400}
    logger.warning("Failed login attempt: %s", username)
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/auth/me")
@limiter.limit("30/minute")
def get_me(request: Request, user=Depends(verify_token)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"username": user["sub"], "role": user.get("role", "analyst")}


# ---- Environment ---------------------------------------------------------

@app.get("/api/environment")
@limiter.limit("60/minute")
def get_environment(request: Request):
    """Return the simulated environment topology."""
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
    """List all available attack scenarios."""
    return _orchestrator.attack_engine.list_scenarios()


@app.get("/api/scenarios/{scenario_id}")
@limiter.limit("60/minute")
def get_scenario(request: Request, scenario_id: str):
    scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{scenario_id}' not found")
    return scenario


@app.post("/api/scenarios/custom")
@limiter.limit("30/minute")
def save_custom_scenario(request: Request, scenario: dict):
    """Save a custom scenario to the scenarios/custom/ directory."""
    custom_dir = PROJECT_ROOT / "scenarios" / "custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    sid = scenario.get("id", f"sc-custom-{len(list(custom_dir.glob('*.json'))) + 1}")
    scenario["id"] = sid
    filepath = custom_dir / f"{sid}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=2)
    # Reload scenarios
    _orchestrator.attack_engine.load_scenarios()
    return {"status": "saved", "id": sid, "path": str(filepath)}


# ---- Simulation ----------------------------------------------------------

@app.post("/api/simulate", response_model=SimulationSummary)
@limiter.limit("10/minute")
async def run_simulation(request: Request, req: SimulationRequest):
    """Run a full simulation for the given scenario and return a summary."""
    scenario = _orchestrator.attack_engine.get_scenario(req.scenario_id)
    if scenario is None:
        raise HTTPException(404, f"Scenario '{req.scenario_id}' not found")

    logger.info("Simulation started: %s", req.scenario_id)

    # Create a fresh orchestrator to avoid state leakage
    orch = SimulationOrchestrator()
    orch.initialise()

    result = orch.run_simulation(
        scenario_id=req.scenario_id,
        duration_minutes=req.duration_minutes,
        normal_intensity=req.normal_intensity,
    )

    _results_cache[req.scenario_id] = result

    # Save to database
    try:
        save_run(req.scenario_id, scenario.get("name", ""), result)
    except Exception as e:
        logger.error("Could not save to database: %s", e)

    scores = result["scores"]
    logger.info("Simulation complete: %s (score: %.1f)", req.scenario_id, scores["overall_score"])
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
    """Stream simulation events in real-time via WebSocket for dramatic live display."""
    # Validate JWT token from query parameter
    if token is None:
        await websocket.close(code=4001, reason="Missing authentication token")
        return
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await websocket.accept()

    try:
        scenario = _orchestrator.attack_engine.get_scenario(scenario_id)
        if scenario is None:
            await websocket.send_json({"type": "error", "message": f"Scenario '{scenario_id}' not found"})
            await websocket.close()
            return

        # Run full simulation in a thread to avoid blocking the async event loop
        import asyncio as _aio
        loop = _aio.get_event_loop()
        orch = SimulationOrchestrator()
        orch.initialise()
        result = await loop.run_in_executor(
            None,
            lambda: orch.run_simulation(scenario_id=scenario_id, duration_minutes=60)
        )
        _results_cache[scenario_id] = result

        # Save to database
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


# ---- Results -------------------------------------------------------------

@app.get("/api/results/{scenario_id}")
@limiter.limit("60/minute")
def get_full_results(request: Request, scenario_id: str):
    """Return the full simulation result for a previously run scenario."""
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]


@app.get("/api/results/{scenario_id}/alerts")
@limiter.limit("60/minute")
def get_alerts(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["alerts"]


@app.get("/api/results/{scenario_id}/incidents")
@limiter.limit("60/minute")
def get_incidents(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["incidents"]


@app.get("/api/results/{scenario_id}/timeline")
@limiter.limit("60/minute")
def get_timeline(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["timeline"]


@app.get("/api/results/{scenario_id}/scores")
@limiter.limit("60/minute")
def get_scores(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["scores"]


@app.get("/api/results/{scenario_id}/mitre")
@limiter.limit("60/minute")
def get_mitre_coverage(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["mitre_coverage"]


@app.get("/api/results/{scenario_id}/report")
@limiter.limit("60/minute")
def get_report(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["report"]


@app.get("/api/results/{scenario_id}/logs")
@limiter.limit("60/minute")
def get_logs(request: Request, scenario_id: str, limit: int = 200, offset: int = 0):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    logs = _results_cache[scenario_id]["logs"]
    return {
        "total": len(logs),
        "offset": offset,
        "limit": limit,
        "data": logs[offset: offset + limit],
    }


@app.get("/api/results/{scenario_id}/ai-analysis")
@limiter.limit("60/minute")
def get_ai_analysis(request: Request, scenario_id: str):
    """Return the AI-generated analyst narrative for a previously run scenario."""
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    ai = _results_cache[scenario_id].get("ai_analysis")
    if ai is None:
        raise HTTPException(404, "AI analysis not available for this simulation run.")
    return ai


@app.get("/api/results/{scenario_id}/statistics")
@limiter.limit("60/minute")
def get_statistics(request: Request, scenario_id: str):
    if scenario_id not in _results_cache:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return _results_cache[scenario_id]["logs_statistics"]


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
def history_delete(request: Request, run_id: int):
    delete_run(run_id)
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
