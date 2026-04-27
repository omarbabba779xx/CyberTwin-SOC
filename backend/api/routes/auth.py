"""Authentication, current-user, audit-log, logout and refresh endpoints."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from backend.audit import get_audit_log, log_action
from backend.auth import (
    JWT_SECRET,
    JWT_ALGORITHM,
    REFRESH_EXPIRY_DAYS,
    authenticate_user,
    create_token,
    create_refresh_token,
    require_permission,
    revoke_token,
    is_token_revoked,
    verify_token,
)

from ..deps import _client_ip, limiter

import jwt as _jwt

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
    from backend.auth import ROLES
    access_token = create_token(user["username"], user["role"])
    refresh_token = create_refresh_token(user["username"], user["role"])
    log_action("LOGIN", username=user["username"], role=user["role"], ip_address=ip)
    return {
        "token": access_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "permissions": sorted(ROLES.get(user["role"], set())),
        "expires_in": int(os.getenv("JWT_EXPIRY_HOURS", "1")) * 3600,
    }


@router.get("/api/auth/me")
@limiter.limit("30/minute")
def get_me(request: Request, user=Depends(verify_token)):
    return {
        "username": user["sub"],
        "role": user.get("role", "viewer"),
        "permissions": user.get("permissions", []),
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
    access_token = create_token(username, role)
    new_refresh_token = create_refresh_token(username, role)

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
