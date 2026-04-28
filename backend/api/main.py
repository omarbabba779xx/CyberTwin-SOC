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
import traceback
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from backend.api.errors import (
    CyberTwinError,
    error_response,
    INTERNAL_ERROR,
    RATE_LIMITED,
)

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
    from backend.observability.tracing import init_tracing
    init_tracing(app)
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

from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402

from backend.observability.middleware import RequestIdMiddleware  # noqa: E402
from backend.observability.metrics import MetricsMiddleware  # noqa: E402
from backend.observability.security_headers import SecurityHeadersMiddleware  # noqa: E402
from backend.middleware.tenant import TenantScopeMiddleware  # noqa: E402


class APIVersionMiddleware(BaseHTTPMiddleware):
    """Stamp every response with X-API-Version so clients can detect future v2 migrations."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-API-Version"] = "v1"
        return response


# Per-request body cap. Enforced at the ASGI layer BEFORE FastAPI parses
# the body so very large uploads cannot exhaust uvicorn worker memory.
# Default 16 MiB; override via MAX_REQUEST_BODY_BYTES.
MAX_BODY_BYTES = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(16 * 1024 * 1024)))


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose declared Content-Length exceeds MAX_BODY_BYTES.

    Falls through for chunked / streamed requests, which are bounded by
    the reverse proxy (`nginx.ingress.kubernetes.io/proxy-body-size: 16m`)
    in production. The starlette layer also caps any single chunk read.
    """

    async def dispatch(self, request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > MAX_BODY_BYTES:
                    return error_response(
                        code="REQUEST_ENTITY_TOO_LARGE",
                        message=f"Request body exceeds {MAX_BODY_BYTES} bytes.",
                        status_code=413,
                        request=request,
                    )
            except ValueError:
                return error_response(
                    code="BAD_REQUEST",
                    message="Invalid Content-Length header.",
                    status_code=400,
                    request=request,
                )
        return await call_next(request)


app.add_middleware(APIVersionMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(MaxBodySizeMiddleware)
app.add_middleware(TenantScopeMiddleware)
app.add_middleware(RequestIdMiddleware)

app.state.limiter = limiter


@app.exception_handler(CyberTwinError)
async def cybertwin_error_handler(request: Request, exc: CyberTwinError):
    return error_response(
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        request=request,
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code_map = {
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMITED",
    }
    return error_response(
        code=code_map.get(exc.status_code, f"HTTP_{exc.status_code}"),
        message=str(exc.detail),
        status_code=exc.status_code,
        request=request,
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc):
    return error_response(
        code=RATE_LIMITED,
        message="Too many requests. Please slow down.",
        status_code=429,
        request=request,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception:\n%s", traceback.format_exc())
    return error_response(
        code=INTERNAL_ERROR,
        message="An unexpected internal error occurred.",
        status_code=500,
        request=request,
    )


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
