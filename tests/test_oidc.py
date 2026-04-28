"""Integration tests for OIDC/SSO with a self-signed mock provider.

Verifies:
- is_oidc_enabled() driven by environment
- ID token validation accepts well-formed tokens
- ID token validation rejects wrong issuer
- ID token validation rejects wrong audience
- ID token validation rejects expired tokens
- ID token validation rejects bad signatures (different key)
- oidc_user_to_local() role mapping (custom claim, roles array, groups, fallback)
"""
from __future__ import annotations

import time
from typing import Any

import pytest
from authlib.jose import JsonWebKey, jwt as jose_jwt


@pytest.fixture
def rsa_keypair():
    """Generate an RSA keypair for signing test ID tokens."""
    key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    return key


@pytest.fixture
def oidc_env(monkeypatch, rsa_keypair):
    """Configure OIDC env + monkeypatch JWKS fetch to return our test key."""
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.test.local")
    monkeypatch.setenv("OIDC_CLIENT_ID", "cybertwin-test-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-secret")

    # Reload the OIDC module so it picks up the env vars
    import backend.auth.oidc as oidc_mod
    oidc_mod._config = None
    oidc_mod._discovery_cache = None
    oidc_mod._jwks_cache = None

    # Build a public-key JWKS containing our signing key
    public_key = rsa_keypair.as_dict(is_private=False)
    public_key["kid"] = "test-key-1"
    public_key["use"] = "sig"
    public_key["alg"] = "RS256"
    jwks = JsonWebKey.import_key_set({"keys": [public_key]})
    oidc_mod._jwks_cache = jwks

    # Discovery cache (avoids HTTP)
    oidc_mod._discovery_cache = {
        "issuer": "https://idp.test.local",
        "authorization_endpoint": "https://idp.test.local/authorize",
        "token_endpoint": "https://idp.test.local/token",
        "jwks_uri": "https://idp.test.local/.well-known/jwks.json",
    }

    yield rsa_keypair

    oidc_mod._config = None
    oidc_mod._discovery_cache = None
    oidc_mod._jwks_cache = None


def _make_id_token(
    private_key,
    iss: str = "https://idp.test.local",
    aud: str = "cybertwin-test-client",
    sub: str = "user-42",
    email: str = "alice@example.com",
    extra: dict[str, Any] | None = None,
    expires_in: int = 600,
) -> str:
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "email": email,
        "iat": now,
        "exp": now + expires_in,
        "nbf": now - 5,
    }
    if extra:
        claims.update(extra)
    header = {"alg": "RS256", "kid": "test-key-1"}
    return jose_jwt.encode(header, claims, private_key).decode("ascii")


class TestEnablement:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("OIDC_ENABLED", raising=False)
        import backend.auth.oidc as oidc_mod
        oidc_mod._config = None
        assert oidc_mod.is_oidc_enabled() is False

    def test_enabled_when_all_env_set(self, oidc_env):
        from backend.auth.oidc import is_oidc_enabled
        assert is_oidc_enabled() is True

    def test_disabled_if_missing_client_id(self, monkeypatch):
        monkeypatch.setenv("OIDC_ENABLED", "true")
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://idp.test.local")
        monkeypatch.delenv("OIDC_CLIENT_ID", raising=False)
        import backend.auth.oidc as oidc_mod
        oidc_mod._config = None
        assert oidc_mod.is_oidc_enabled() is False


class TestIDTokenValidation:
    def test_valid_token_accepted(self, oidc_env):
        from backend.auth.oidc import validate_id_token
        token = _make_id_token(oidc_env)
        claims = validate_id_token(token)
        assert claims["sub"] == "user-42"
        assert claims["email"] == "alice@example.com"

    def test_wrong_issuer_rejected(self, oidc_env):
        from backend.auth.oidc import validate_id_token
        token = _make_id_token(oidc_env, iss="https://attacker.example.com")
        with pytest.raises(Exception):
            validate_id_token(token)

    def test_wrong_audience_rejected(self, oidc_env):
        from backend.auth.oidc import validate_id_token
        token = _make_id_token(oidc_env, aud="some-other-app")
        with pytest.raises(Exception):
            validate_id_token(token)

    def test_audience_array_accepted(self, oidc_env):
        from backend.auth.oidc import validate_id_token
        token = _make_id_token(
            oidc_env, aud=["cybertwin-test-client", "other-relying-party"]
        )
        claims = validate_id_token(token)
        assert claims["sub"] == "user-42"

    def test_expired_token_rejected(self, oidc_env):
        from backend.auth.oidc import validate_id_token
        token = _make_id_token(oidc_env, expires_in=-60)
        with pytest.raises(Exception):
            validate_id_token(token)

    def test_bad_signature_rejected(self, oidc_env):
        """Signing with a different key must fail validation."""
        from backend.auth.oidc import validate_id_token
        attacker_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
        token = _make_id_token(attacker_key)
        with pytest.raises(Exception):
            validate_id_token(token)


class TestRoleMapping:
    def test_custom_role_claim_takes_priority(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "email": "a@x.com",
            "cybertwin_role": "soc_manager",
            "groups": ["admin"],  # would normally win — but custom claim takes priority
        })
        assert local["role"] == "soc_manager"

    def test_roles_array_mapped(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "email": "a@x.com",
            "roles": ["analyst"],
        })
        assert local["role"] == "analyst"

    def test_groups_array_mapped_when_no_roles(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "email": "a@x.com",
            "groups": ["viewer"],
        })
        assert local["role"] == "viewer"

    def test_unknown_group_falls_back_to_viewer(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "email": "a@x.com",
            "groups": ["random-ad-group"],
        })
        assert local["role"] == "viewer"

    def test_no_email_falls_back_to_preferred_username(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "preferred_username": "alice@example.org",
        })
        assert local["username"] == "alice@example.org"

    def test_tenant_id_propagated(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({
            "sub": "u1",
            "email": "a@x.com",
            "tenant_id": "tenant-acme",
        })
        assert local["tenant_id"] == "tenant-acme"

    def test_provider_marked_as_oidc(self):
        from backend.auth.oidc import oidc_user_to_local
        local = oidc_user_to_local({"sub": "u1", "email": "a@x.com"})
        assert local["provider"] == "oidc"
