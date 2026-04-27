"""Authentication, current-user, and audit-log endpoints."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from backend.audit import get_audit_log, log_action
from backend.auth import (
    authenticate_user,
    create_token,
    require_permission,
    verify_token,
)

from ..deps import _client_ip, limiter

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


@router.get("/api/auth/me")
@limiter.limit("30/minute")
def get_me(request: Request, user=Depends(verify_token)):
    return {
        "username": user["sub"],
        "role": user.get("role", "viewer"),
        "permissions": user.get("permissions", []),
    }


@router.get("/api/audit")
@limiter.limit("30/minute")
def audit_log(
    request: Request,
    limit: int = 200,
    user=Depends(require_permission("view_audit_log")),
):
    log_action(
        "VIEW_AUDIT_LOG",
        username=user["sub"],
        role=user.get("role"),
        ip_address=_client_ip(request),
    )
    return get_audit_log(limit=limit)
