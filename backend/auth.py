"""
CyberTwin SOC — Centralized Authentication & RBAC Module
==========================================================
Provides bcrypt password hashing, JWT creation/verification,
role-based access control (RBAC), and audit trail helpers.

Roles hierarchy:
    admin   → full access (manage users, delete history, configure)
    analyst → run simulations, view all results, manage scenarios
    viewer  → read-only access to results and reports
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt as _bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("cybertwin.auth")

# ---------------------------------------------------------------------------
# Password hashing (bcrypt direct — passlib 1.7.4 incompatible with bcrypt 4.x)
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain*."""
    return _bcrypt.hashpw(plain.encode("utf-8"), _bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* string."""
    try:
        return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT secret — persisted so tokens survive restarts
# ---------------------------------------------------------------------------

_SECRET_FILE = Path(__file__).resolve().parent.parent / "data" / ".jwt_secret"


def _load_or_create_secret() -> str:
    env_secret = os.getenv("JWT_SECRET")
    if env_secret and len(env_secret) >= 32:
        return env_secret
    _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _SECRET_FILE.exists():
        return _SECRET_FILE.read_text().strip()
    secret = secrets.token_hex(48)
    _SECRET_FILE.write_text(secret)
    logger.info("Generated new persistent JWT secret → %s", _SECRET_FILE)
    return secret


JWT_SECRET: str = _load_or_create_secret()
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_HOURS: int = int(os.getenv("JWT_EXPIRY_HOURS", "1"))
REFRESH_EXPIRY_DAYS: int = int(os.getenv("REFRESH_EXPIRY_DAYS", "7"))

# ---------------------------------------------------------------------------
# Role definitions & permissions
# ---------------------------------------------------------------------------

"""Phase 5 RBAC model.

The 3 legacy roles (admin / analyst / viewer) remain valid for backward
compatibility. They now alias an explicit permission set that combines
the legacy permission strings with the new scoped ones (`case:read`,
`rule:create`, `simulation:run`, `audit:read`, `connector:manage`,
`tenant:admin`, ...).

Six additional roles are introduced for enterprise tenants:
  - platform_admin   - everything, including tenant management
  - soc_manager      - run sims, manage cases, approve suppressions
  - senior_analyst   - case:assign + rule:approve + simulation:run
  - tier1_analyst    - case:read/write but no rule changes
  - detection_eng    - rule:create / rule:approve / rule:deploy
  - threat_hunter    - simulation:run + ingestion:write + ai:evidence
  - auditor          - case:read + audit:read + everything read-only
  - read_executive   - dashboards / reports / coverage only
  - service_account  - api keys (programmatic ingestion)
"""

# ---- Permission catalogue ---------------------------------------------------

# Scoped permissions (resource:action). Use these in new code.
PERMISSIONS_SCOPED = {
    # cases
    "case:read", "case:write", "case:assign", "case:close",
    # rules
    "rule:read", "rule:create", "rule:approve", "rule:deploy", "rule:delete",
    # simulations
    "simulation:run", "simulation:read",
    # ingestion
    "ingestion:write", "ingestion:read", "ingestion:admin",
    # audit + tenant
    "audit:read", "audit:export",
    "connector:manage", "connector:read",
    "tenant:admin",
    # ai
    "ai:evidence", "ai:run",
    # admin
    "feedback:write", "suppression:create", "suppression:delete",
}

# Legacy permission strings used by existing endpoints. Kept verbatim.
PERMISSIONS_LEGACY = {
    "run_simulation", "view_results", "manage_scenarios", "delete_history",
    "view_history", "manage_users", "view_audit_log", "configure_system",
}


def _all_perms() -> set[str]:
    return PERMISSIONS_SCOPED | PERMISSIONS_LEGACY


# Shared permission base for soc_manager / senior_analyst.
_SOC_MANAGER_BASE: set[str] = {
    "run_simulation", "view_results", "view_history",
    "case:read", "case:write", "case:assign", "case:close",
    "simulation:run", "simulation:read",
    "feedback:write", "suppression:create", "suppression:delete",
    "rule:read", "audit:read",
    "connector:read", "ingestion:read",
    "ai:evidence", "ai:run",
}


ROLES: dict[str, set[str]] = {
    # ---- Legacy roles (kept for backward compatibility) ------------------
    "admin": _all_perms(),

    "analyst": (
        {"run_simulation", "view_results", "manage_scenarios", "view_history"}
        | {"case:read", "case:write", "case:assign", "case:close",
           "simulation:run", "simulation:read",
           "ingestion:write", "ingestion:read",
           "feedback:write", "ai:evidence", "ai:run",
           "rule:read", "connector:read"}
    ),

    "viewer": {"view_results", "view_history",
               "case:read", "simulation:read", "rule:read", "connector:read"},

    # ---- New enterprise roles -------------------------------------------
    "platform_admin": _all_perms(),

    "soc_manager": _SOC_MANAGER_BASE,
    "senior_analyst": _SOC_MANAGER_BASE | {"rule:approve"},

    "tier1_analyst": {
        "view_results", "view_history",
        "case:read", "case:write",
        "simulation:read", "rule:read", "ai:evidence",
        "feedback:write",
    },

    "detection_engineer": {
        "view_results", "view_history",
        "rule:read", "rule:create", "rule:approve", "rule:deploy", "rule:delete",
        "simulation:run", "simulation:read",
        "ingestion:read", "case:read",
    },

    "threat_hunter": {
        "view_results", "view_history",
        "simulation:run", "simulation:read",
        "ingestion:write", "ingestion:read",
        "case:read", "rule:read",
        "ai:evidence", "ai:run", "connector:read",
    },

    "auditor": {
        "view_results", "view_history", "view_audit_log",
        "audit:read", "audit:export",
        "case:read", "rule:read", "simulation:read",
        "connector:read", "ingestion:read",
    },

    "read_executive": {
        "view_results", "view_history",
        "simulation:read", "case:read", "rule:read", "ai:evidence",
    },

    "service_account": {
        "ingestion:write", "ingestion:read", "simulation:read",
        "case:read", "rule:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLES.get(role, set())


# ---------------------------------------------------------------------------
# Token creation / verification
# ---------------------------------------------------------------------------

security = HTTPBearer(auto_error=False)


def create_token(username: str, role: str = "analyst") -> str:
    """Create a signed access JWT for *username* with the given *role*.

    Includes a unique ``jti`` (JWT ID) used for token revocation via the
    Redis / in-memory denylist.
    """
    if role not in ROLES:
        role = "viewer"
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "permissions": list(ROLES[role]),
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_hex(16),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(username: str, role: str = "analyst") -> str:
    """Create a long-lived refresh JWT. Rotated on each use."""
    if role not in ROLES:
        role = "viewer"
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(days=REFRESH_EXPIRY_DAYS),
        "jti": secrets.token_hex(16),
        "type": "refresh",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# Token revocation denylist (Redis-backed when available, in-memory fallback)
# ---------------------------------------------------------------------------

def revoke_token(jti: str, remaining_ttl_seconds: int) -> None:
    """Add *jti* to the revocation denylist with appropriate TTL.

    Uses the shared cache (Redis when available). Once the token's natural
    expiry passes the entry is evicted automatically.
    """
    from backend.cache import cache
    cache.set(f"revoked_jti:{jti}", "1", ttl=max(remaining_ttl_seconds, 1))


def is_token_revoked(jti: str) -> bool:
    """Return True if *jti* appears in the denylist."""
    from backend.cache import cache
    return cache.get(f"revoked_jti:{jti}") is not None


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """Verify JWT and return the payload. Raises 401 if invalid/missing/revoked."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired — please log in again")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    if payload.get("type", "access") != "access":
        raise HTTPException(status_code=401, detail="Refresh token cannot be used here")

    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked — please log in again")

    return payload


def verify_token_optional(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Optional[dict[str, Any]]:
    """Like verify_token but returns None instead of raising for missing tokens."""
    if credentials is None:
        return None
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        return None
    return payload


def require_permission(permission: str):
    """FastAPI dependency factory — raises 403 if the user lacks *permission*."""
    def _check(user: dict = Depends(verify_token)) -> dict:
        role = user.get("role", "viewer")
        if not has_permission(role, permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required (your role: {role})",
            )
        return user
    return _check


# ---------------------------------------------------------------------------
# Default user store (hashed passwords, loaded from environment)
# ---------------------------------------------------------------------------

def _build_user_store() -> dict[str, dict[str, str]]:
    """Build the user store with bcrypt-hashed passwords from environment."""
    defaults = {
        "admin": (os.getenv("AUTH_ADMIN_PASSWORD", "changeme-admin"), "admin"),
        "analyst": (os.getenv("AUTH_ANALYST_PASSWORD", "changeme-analyst"), "analyst"),
        "viewer": (os.getenv("AUTH_VIEWER_PASSWORD", "changeme-viewer"), "viewer"),
    }
    store: dict[str, dict[str, str]] = {}
    for username, (password, role) in defaults.items():
        store[username] = {
            "hashed_password": hash_password(password),
            "role": role,
        }
    return store


_USER_STORE: dict[str, dict[str, str]] = _build_user_store()


def authenticate_user(username: str, password: str) -> Optional[dict[str, str]]:
    """Return user dict if credentials are valid, else None."""
    user = _USER_STORE.get(username)
    if user is None:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return {"username": username, "role": user["role"]}


# ---------------------------------------------------------------------------
# Production safety
# ---------------------------------------------------------------------------

_DEFAULT_PASSWORDS = {
    "changeme-admin", "changeme-analyst", "changeme-viewer",
    "admin", "password", "123456", "cybertwin", "soc",
}

_DEFAULT_JWT_SECRETS = {
    "your-secret-key-here", "changeme", "secret", "test-secret",
}


def check_production_safety() -> None:
    """Refuse to start in production mode if defaults / weak secrets are used.

    Triggered only when the ENV environment variable is set to 'production'.
    Raises RuntimeError with a clear, actionable message.
    """
    env = os.getenv("ENV", "").lower()
    if env not in ("production", "prod"):
        # Issue a soft warning in dev
        if os.getenv("AUTH_ADMIN_PASSWORD", "") in _DEFAULT_PASSWORDS:
            logger.warning(
                "\u26a0\ufe0f  AUTH_ADMIN_PASSWORD looks like a default. "
                "Change it before any non-local deployment."
            )
        return

    problems: list[str] = []

    # JWT secret
    env_secret = os.getenv("JWT_SECRET", "")
    if not env_secret:
        problems.append("JWT_SECRET is not set. Generate one with: openssl rand -hex 32")
    elif len(env_secret) < 64:
        problems.append(f"JWT_SECRET is too short ({len(env_secret)} chars, minimum 64 for production).")
    elif env_secret.lower() in _DEFAULT_JWT_SECRETS:
        problems.append("JWT_SECRET uses a known default value.")

    # Default passwords
    for var in ("AUTH_ADMIN_PASSWORD", "AUTH_ANALYST_PASSWORD", "AUTH_VIEWER_PASSWORD"):
        val = os.getenv(var, "")
        if not val:
            problems.append(f"{var} is not set.")
        elif val in _DEFAULT_PASSWORDS or len(val) < 12:
            problems.append(f"{var} is weak or uses a default value.")

    if problems:
        message = (
            "\u274c CyberTwin SOC refused to start in production mode "
            "due to the following security issues:\n  - "
            + "\n  - ".join(problems)
            + "\n\nFix these in your .env file (or environment) and restart. "
              "To override (NOT recommended), set ENV=development."
        )
        logger.error(message)
        raise RuntimeError(message)
