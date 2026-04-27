"""
CyberTwin SOC — FastAPI Application Entry Point

Responsible for:
  - FastAPI app creation + middleware (CORS, security headers, metrics, request-ID)
  - Rate limiter wiring
  - Lifespan (startup / shutdown)
  - Including all domain routers

Business logic lives in backend.api.routes.* — not here.
"""

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cybertwin")

from backend.observability.logging_setup import auto_configure as _setup_logs  # noqa: E402
_setup_logs()

from backend.api.deps import limiter, orchestrator as _orchestrator  # noqa: E402
from backend.database import init_db  # noqa: E402
from backend.auth import check_production_safety  # noqa: E402
from backend.audit import init_audit_table  # noqa: E402
from backend.cache import cache  # noqa: E402


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("CyberTwin SOC API v%s starting...", os.getenv("APP_VERSION", "3.0"))
    logger.info("Cache backend: %s", cache.backend)
    check_production_safety()
    _orchestrator.initialise()
    logger.info("Orchestrator ready — %d scenarios loaded",
                len(_orchestrator.attack_engine._scenarios))
    from backend.soc import init_soc_tables
    init_soc_tables()
    logger.info("SOC tables ready (feedback, cases, suppressions)")
    yield
    logger.info("CyberTwin SOC API shutting down...")


# ---------------------------------------------------------------------------
# App + middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberTwin SOC API",
    description=(
        "Enterprise Digital Twin platform for cyber attack simulation, "
        "detection validation, and SOC readiness."
    ),
    version=os.getenv("APP_VERSION", "3.0.0"),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3001").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

from backend.observability.middleware import RequestIdMiddleware  # noqa: E402
from backend.observability.metrics import MetricsMiddleware  # noqa: E402
from backend.observability.security_headers import SecurityHeadersMiddleware  # noqa: E402

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
# Domain routers
# ---------------------------------------------------------------------------

from backend.api.routes import (  # noqa: E402
    auth as auth_routes,
    coverage as coverage_routes,
    environment as environment_routes,
    health as health_routes,
    history as history_routes,
    ingestion as ingestion_routes,
    mitre as mitre_routes,
    results as results_routes,
    scenarios as scenarios_routes,
    simulation as simulation_routes,
    soar as soar_routes,
    soc as soc_routes,
    tasks as tasks_routes,
)

app.include_router(health_routes.router)
app.include_router(auth_routes.router)
app.include_router(environment_routes.router)
app.include_router(history_routes.router)
app.include_router(scenarios_routes.router)
app.include_router(simulation_routes.router)
app.include_router(results_routes.router)
app.include_router(ingestion_routes.router)
app.include_router(coverage_routes.router)
app.include_router(soc_routes.router)
app.include_router(soar_routes.router)
app.include_router(mitre_routes.router)
app.include_router(tasks_routes.router)
