"""OIDC/SSO provider integration for enterprise authentication.

Supports any OpenID Connect provider (Entra ID, Okta, Keycloak, Auth0).
Configuration via environment variables:
  OIDC_ENABLED=true
  OIDC_ISSUER_URL=https://login.microsoftonline.com/{tenant}/v2.0
  OIDC_CLIENT_ID=...
  OIDC_CLIENT_SECRET=...
  OIDC_REDIRECT_URI=http://localhost:8000/api/auth/oidc/callback
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, jwt as jose_jwt

logger = logging.getLogger("cybertwin.auth.oidc")

_OIDC_ROLE_MAP_DEFAULT: dict[str, str] = {
    "admin": "admin",
    "soc_manager": "soc_manager",
    "analyst": "analyst",
    "viewer": "viewer",
}


@dataclass(frozen=True)
class OIDCConfig:
    """Configuration for the OIDC/SSO provider, read from environment."""

    enabled: bool = field(default=False)
    issuer_url: str = field(default="")
    client_id: str = field(default="")
    client_secret: str = field(default="")
    redirect_uri: str = field(default="http://localhost:8000/api/auth/oidc/callback")
    scopes: str = field(default="openid email profile")

    @classmethod
    def from_env(cls) -> OIDCConfig:
        return cls(
            enabled=os.getenv("OIDC_ENABLED", "false").lower() in ("true", "1", "yes"),
            issuer_url=os.getenv("OIDC_ISSUER_URL", "").rstrip("/"),
            client_id=os.getenv("OIDC_CLIENT_ID", ""),
            client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
            redirect_uri=os.getenv(
                "OIDC_REDIRECT_URI",
                "http://localhost:8000/api/auth/oidc/callback",
            ),
            scopes=os.getenv("OIDC_SCOPES", "openid email profile"),
        )


_config: OIDCConfig | None = None


def _get_config() -> OIDCConfig:
    global _config
    if _config is None:
        _config = OIDCConfig.from_env()
    return _config


def is_oidc_enabled() -> bool:
    cfg = _get_config()
    return cfg.enabled and bool(cfg.issuer_url) and bool(cfg.client_id)


def _discovery_url(cfg: OIDCConfig) -> str:
    return f"{cfg.issuer_url}/.well-known/openid-configuration"


_discovery_cache: dict[str, Any] | None = None


def _fetch_discovery(cfg: OIDCConfig) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    global _discovery_cache
    if _discovery_cache is not None:
        return _discovery_cache
    resp = httpx.get(_discovery_url(cfg), timeout=10)
    resp.raise_for_status()
    _discovery_cache = resp.json()
    return _discovery_cache


_jwks_cache: Any = None


def _fetch_jwks(cfg: OIDCConfig) -> Any:
    """Fetch and cache the JWKS from the issuer."""
    global _jwks_cache
    if _jwks_cache is not None:
        return _jwks_cache
    discovery = _fetch_discovery(cfg)
    jwks_uri = discovery["jwks_uri"]
    resp = httpx.get(jwks_uri, timeout=10)
    resp.raise_for_status()
    _jwks_cache = JsonWebKey.import_key_set(resp.json())
    return _jwks_cache


def get_oidc_authorization_url() -> str:
    """Construct the OIDC authorization URL with state and nonce."""
    cfg = _get_config()
    if not is_oidc_enabled():
        raise RuntimeError("OIDC is not enabled")

    discovery = _fetch_discovery(cfg)
    authorization_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    # Store state+nonce in cache for validation on callback
    from backend.cache import cache
    cache.set(f"oidc_state:{state}", nonce, ttl=600)

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scopes,
        "state": state,
        "nonce": nonce,
    }
    return f"{authorization_endpoint}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> dict[str, Any]:
    """Exchange an authorization code for tokens via the token endpoint."""
    cfg = _get_config()
    discovery = _fetch_discovery(cfg)
    token_endpoint = discovery["token_endpoint"]

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": cfg.redirect_uri,
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


def validate_id_token(id_token: str) -> dict[str, Any]:
    """Decode and validate an OIDC ID token using the issuer's JWKS.

    Returns the validated claims dict.
    Raises on expired, invalid signature, or bad issuer/audience.
    """
    cfg = _get_config()
    jwks = _fetch_jwks(cfg)

    claims = jose_jwt.decode(id_token, jwks)
    claims.validate()

    # Verify issuer
    if claims.get("iss") != cfg.issuer_url:
        iss = claims.get("iss", "")
        if not iss.rstrip("/") == cfg.issuer_url.rstrip("/"):
            raise ValueError(
                f"ID token issuer mismatch: expected {cfg.issuer_url}, got {iss}"
            )

    # Verify audience
    aud = claims.get("aud")
    valid_aud = aud == cfg.client_id or (isinstance(aud, list) and cfg.client_id in aud)
    if not valid_aud:
        raise ValueError(
            f"ID token audience mismatch: expected {cfg.client_id}, got {aud}"
        )

    return dict(claims)


def oidc_user_to_local(claims: dict[str, Any]) -> dict[str, Any]:
    """Map OIDC claims to the local user format used by CyberTwin SOC.

    Role mapping priority:
      1. ``cybertwin_role`` custom claim (set in the IdP)
      2. ``roles`` array claim (Entra ID style)
      3. ``groups`` array claim (Keycloak / Okta style)
      4. Falls back to ``viewer``
    """
    email = claims.get("email", claims.get("preferred_username", "unknown"))
    name = claims.get("name", email)

    role = "viewer"

    custom_role = claims.get("cybertwin_role")
    if custom_role and custom_role in _OIDC_ROLE_MAP_DEFAULT:
        role = _OIDC_ROLE_MAP_DEFAULT[custom_role]
    else:
        idp_roles = claims.get("roles", []) or claims.get("groups", [])
        if isinstance(idp_roles, list):
            for idp_role in idp_roles:
                mapped = _OIDC_ROLE_MAP_DEFAULT.get(str(idp_role).lower())
                if mapped:
                    role = mapped
                    break

    return {
        "username": email,
        "name": name,
        "email": email,
        "role": role,
        "tenant_id": claims.get("tenant_id", "default"),
        "oidc_subject": claims.get("sub", ""),
        "provider": "oidc",
    }
