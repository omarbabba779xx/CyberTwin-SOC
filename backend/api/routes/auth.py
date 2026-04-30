"""Authentication, current-user, audit-log, logout and refresh endpoints."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from backend.audit import get_audit_log, log_action
from backend.auth import (
    JWT_SECRET,
    JWT_ALGORITHM,
    REFRESH_EXPIRY_DAYS,
    authenticate_user,
    create_token,
    create_refresh_token,
    permissions_for_role,
    require_permission,
    revoke_all_sessions,
    revoke_token,
    is_token_revoked,
    verify_token,
)
from backend.auth.oidc import (
    is_oidc_enabled,
    get_oidc_authorization_url,
    exchange_code_for_tokens,
    validate_id_token,
    oidc_user_to_local,
)

from ..deps import _client_ip, limiter

import jwt as _jwt

logger = logging.getLogger("cybertwin.auth.routes")

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(request: Request, data: LoginRequest):
    ip = _client_ip(request)
    user = authenticate_user(data.username, data.password)
    if user is None:
        log_action("LOGIN", username=data.username, ip_address=ip, status="failure")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    tenant_id = user.get("tenant_id", "default")
    access_token = create_token(user["username"], user["role"], tenant_id=tenant_id)
    refresh_token = create_refresh_token(user["username"], user["role"], tenant_id=tenant_id)
    log_action("LOGIN", username=user["username"], role=user["role"], ip_address=ip)
    return {
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "permissions": sorted(permissions_for_role(user["role"], tenant_id)),
        "expires_in": int(os.getenv("JWT_EXPIRY_HOURS", "1")) * 3600,
    }


@router.get("/api/auth/me")
@limiter.limit("30/minute")
def get_me(request: Request, user=Depends(verify_token)):
    role = user.get("role", "viewer")
    tenant_id = user.get("tenant_id", "default")
    return {
        "username": user["sub"],
        "role": role,
        "tenant_id": tenant_id,
        "permissions": sorted(permissions_for_role(role, tenant_id)),
    }


@router.post("/api/auth/logout")
@limiter.limit("30/minute")
def logout(request: Request, user=Depends(verify_token)):
    """Revoke the current access token (add its jti to the denylist)."""
    jti = user.get("jti")
    if jti:
        exp = user.get("exp", 0)
        remaining = max(0, int(exp - datetime.now(timezone.utc).timestamp()))
        revoke_token(jti, remaining)
    log_action("LOGOUT", username=user["sub"], role=user.get("role"),
               ip_address=_client_ip(request))
    return {"status": "logged_out"}


@router.post("/api/auth/revoke-all")
@limiter.limit("5/minute")
def revoke_all(request: Request, user=Depends(verify_token)):
    """Revoke every active session for the authenticated user."""
    username = user["sub"]
    count = revoke_all_sessions(username)
    log_action("REVOKE_ALL_SESSIONS", username=username, role=user.get("role"),
               ip_address=_client_ip(request))
    return {"status": "all_sessions_revoked", "revoked": count}


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/api/auth/refresh")
@limiter.limit("10/minute")
def refresh_access_token(request: Request, data: RefreshRequest):
    """Exchange a valid refresh token for a new access + refresh token pair.

    The old refresh token's jti is revoked immediately (rotation).
    """
    try:
        payload = _jwt.decode(data.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except _jwt.ExpiredSignatureError:
        raise HTTPException(401, "Refresh token expired — please log in again")
    except _jwt.InvalidTokenError as exc:
        raise HTTPException(401, f"Invalid refresh token: {exc}")

    if payload.get("type") != "refresh":
        raise HTTPException(401, "Not a refresh token")

    jti = payload.get("jti")
    if jti and is_token_revoked(jti):
        raise HTTPException(401, "Refresh token has been revoked")

    # Rotate: revoke old refresh jti before issuing new tokens
    if jti:
        exp = payload.get("exp", 0)
        remaining = max(0, int(exp - datetime.now(timezone.utc).timestamp()))
        revoke_token(jti, remaining + REFRESH_EXPIRY_DAYS * 86400)

    username = payload["sub"]
    role = payload.get("role", "viewer")
    tenant_id = payload.get("tenant_id", "default")
    access_token = create_token(username, role, tenant_id=tenant_id)
    new_refresh_token = create_refresh_token(username, role, tenant_id=tenant_id)

    log_action("TOKEN_REFRESH", username=username, role=role,
               ip_address=_client_ip(request))
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": int(os.getenv("JWT_EXPIRY_HOURS", "1")) * 3600,
    }


@router.get("/api/audit")
@limiter.limit("30/minute")
def audit_log(
    request: Request,
    limit: int = 200,
    user=Depends(require_permission("view_audit_log")),
):
    limit = min(limit, 1000)
    log_action(
        "VIEW_AUDIT_LOG",
        username=user["sub"],
        role=user.get("role"),
        ip_address=_client_ip(request),
    )
    return get_audit_log(limit=limit)


# ---------------------------------------------------------------------------
# OIDC / SSO endpoints (Phase 3.2) — only active when OIDC_ENABLED=true
# ---------------------------------------------------------------------------


@router.get("/api/auth/oidc/authorize")
@limiter.limit("10/minute")
async def oidc_authorize(request: Request):
    """Redirect the user to the configured OIDC provider's authorization page."""
    if not is_oidc_enabled():
        raise HTTPException(404, "OIDC authentication is not enabled")
    try:
        url = get_oidc_authorization_url()
    except Exception as exc:
        logger.error("Failed to build OIDC authorization URL: %s", exc)
        raise HTTPException(502, "Failed to contact OIDC provider")
    return RedirectResponse(url, status_code=302)


@router.get("/api/auth/oidc/callback")
@limiter.limit("10/minute")
async def oidc_callback(request: Request, code: str = "", state: str = ""):
    """Handle the OIDC callback: exchange code, validate ID token, issue local JWT."""
    if not is_oidc_enabled():
        raise HTTPException(404, "OIDC authentication is not enabled")
    if not code:
        raise HTTPException(400, "Missing authorization code")

    ip = _client_ip(request)

    # Validate state parameter
    from backend.cache import cache
    stored_nonce = cache.get(f"oidc_state:{state}")
    if stored_nonce is None:
        log_action("OIDC_LOGIN", ip_address=ip, status="failure",
                   details={"reason": "invalid_state"})
        raise HTTPException(400, "Invalid or expired state parameter")
    cache.delete(f"oidc_state:{state}")

    try:
        tokens = await exchange_code_for_tokens(code)
    except Exception as exc:
        logger.error("OIDC token exchange failed: %s", exc)
        log_action("OIDC_LOGIN", ip_address=ip, status="failure",
                   details={"reason": "token_exchange_failed"})
        raise HTTPException(502, "Failed to exchange authorization code")

    id_token_raw = tokens.get("id_token")
    if not id_token_raw:
        raise HTTPException(502, "No id_token in provider response")

    try:
        claims = validate_id_token(id_token_raw)
    except Exception as exc:
        logger.error("OIDC ID token validation failed: %s", exc)
        log_action("OIDC_LOGIN", ip_address=ip, status="failure",
                   details={"reason": "id_token_invalid", "error": str(exc)})
        raise HTTPException(401, "Invalid ID token from provider")

    user = oidc_user_to_local(claims)

    access_token = create_token(user["username"], user["role"],
                                tenant_id=user.get("tenant_id", "default"))
    refresh_token = create_refresh_token(user["username"], user["role"],
                                         tenant_id=user.get("tenant_id", "default"))

    log_action("OIDC_LOGIN", username=user["username"], role=user["role"],
               ip_address=ip, details={"provider": "oidc", "sub": user["oidc_subject"]})

    return {
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "permissions": sorted(permissions_for_role(user["role"], user.get("tenant_id", "default"))),
        "expires_in": int(os.getenv("JWT_EXPIRY_HOURS", "1")) * 3600,
        "provider": "oidc",
    }
