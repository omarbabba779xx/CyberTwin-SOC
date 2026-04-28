"""End-to-end JWT session lifecycle tests.

Verifies the full token cycle exposed by /api/auth/* endpoints:

- access token contains a `jti` claim
- /api/auth/me succeeds with a fresh token
- /api/auth/logout adds the jti to the Redis denylist
- subsequent requests with the revoked token return 401
- /api/auth/refresh issues a new access+refresh pair
- the OLD refresh token is rotated (its jti is revoked)
- replaying the old refresh token returns 401
- refresh fails when the supplied token is an access token (type guard)
- /api/auth/revoke-all wipes every active session for the user
- a session beyond MAX_CONCURRENT_SESSIONS evicts the oldest
"""
from __future__ import annotations

import jwt as _jwt
import pytest


@pytest.fixture
def auth_app():
    """FastAPI app with the real auth router wired."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from backend.api.routes.auth import router as auth_router
    from backend.api.deps import limiter

    app = FastAPI()
    app.state.limiter = limiter
    # slowapi 0.1.x exposes the rate-limit exception via _rate_limit_exceeded_handler
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(auth_router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def fresh_cache_and_limiter():
    """Clear cache + slowapi limiter state between tests.

    The auth router applies tight rate limits (5/min on login). For
    integration tests that need to perform multiple logins we reset the
    in-memory limiter storage between tests.
    """
    from backend.cache import cache
    from backend.api.deps import limiter

    try:
        cache.clear()
    except Exception:
        pass

    try:
        limiter.reset()
    except Exception:
        pass

    yield

    try:
        cache.clear()
    except Exception:
        pass
    try:
        limiter.reset()
    except Exception:
        pass


def _login(client) -> dict:
    """Login as the analyst user from the test conftest fixtures."""
    resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "soc2024"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _decode(token: str) -> dict:
    from backend.auth import JWT_SECRET, JWT_ALGORITHM
    return _jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ---------------------------------------------------------------------------
# Access token contains jti + permissions + expiry
# ---------------------------------------------------------------------------

class TestAccessTokenStructure:
    def test_login_returns_access_and_refresh(self, auth_app):
        body = _login(auth_app)
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"

    def test_access_token_contains_jti(self, auth_app):
        body = _login(auth_app)
        decoded = _decode(body["access_token"])
        assert "jti" in decoded and len(decoded["jti"]) == 32  # 16 hex bytes
        assert decoded["type"] == "access"
        assert decoded["sub"] == "analyst"
        assert decoded["role"] == "analyst"

    def test_refresh_token_contains_jti_and_type(self, auth_app):
        body = _login(auth_app)
        decoded = _decode(body["refresh_token"])
        assert "jti" in decoded
        assert decoded["type"] == "refresh"


# ---------------------------------------------------------------------------
# Logout revokes the access-token jti
# ---------------------------------------------------------------------------

class TestLogoutRevokesJTI:
    def test_token_works_before_logout(self, auth_app):
        body = _login(auth_app)
        resp = auth_app.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "analyst"

    def test_logout_adds_jti_to_denylist(self, auth_app):
        from backend.auth import is_token_revoked
        body = _login(auth_app)
        jti = _decode(body["access_token"])["jti"]
        assert is_token_revoked(jti) is False  # before logout

        resp = auth_app.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "logged_out"
        assert is_token_revoked(jti) is True  # after logout

    def test_revoked_token_returns_401(self, auth_app):
        body = _login(auth_app)
        token = body["access_token"]
        auth_app.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = auth_app.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Refresh-token rotation
# ---------------------------------------------------------------------------

class TestRefreshTokenRotation:
    def test_refresh_returns_new_pair(self, auth_app):
        body = _login(auth_app)
        resp = auth_app.post(
            "/api/auth/refresh",
            json={"refresh_token": body["refresh_token"]},
        )
        assert resp.status_code == 200
        new = resp.json()
        assert new["access_token"] != body["access_token"]
        assert new["refresh_token"] != body["refresh_token"]

    def test_old_refresh_jti_is_revoked_after_rotation(self, auth_app):
        from backend.auth import is_token_revoked
        body = _login(auth_app)
        old_refresh_jti = _decode(body["refresh_token"])["jti"]
        assert is_token_revoked(old_refresh_jti) is False

        resp = auth_app.post(
            "/api/auth/refresh",
            json={"refresh_token": body["refresh_token"]},
        )
        assert resp.status_code == 200
        assert is_token_revoked(old_refresh_jti) is True  # rotated

    def test_replaying_old_refresh_returns_401(self, auth_app):
        body = _login(auth_app)
        # First refresh — succeeds and revokes the original jti
        first = auth_app.post(
            "/api/auth/refresh",
            json={"refresh_token": body["refresh_token"]},
        )
        assert first.status_code == 200

        # Second refresh with the SAME (now revoked) refresh_token — must fail
        replay = auth_app.post(
            "/api/auth/refresh",
            json={"refresh_token": body["refresh_token"]},
        )
        assert replay.status_code == 401
        assert "revoked" in replay.json()["detail"].lower()

    def test_access_token_rejected_at_refresh_endpoint(self, auth_app):
        body = _login(auth_app)
        resp = auth_app.post(
            "/api/auth/refresh",
            json={"refresh_token": body["access_token"]},  # wrong type
        )
        assert resp.status_code == 401
        assert "not a refresh token" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Revoke-all wipes every active session
# ---------------------------------------------------------------------------

class TestRevokeAllSessions:
    def test_revoke_all_invalidates_all_open_tokens(self, auth_app):
        from backend.auth import is_token_revoked
        # Open three sessions (three logins → three access tokens with distinct jtis)
        sessions = [_login(auth_app) for _ in range(3)]
        jtis = [_decode(s["access_token"])["jti"] for s in sessions]

        # Use the most recent token to call revoke-all
        resp = auth_app.post(
            "/api/auth/revoke-all",
            headers={"Authorization": f"Bearer {sessions[-1]['access_token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["revoked"] >= 1

        for jti in jtis:
            assert is_token_revoked(jti) is True


# ---------------------------------------------------------------------------
# Session governance — concurrent-session cap
# ---------------------------------------------------------------------------

class TestConcurrentSessionCap:
    def test_oldest_session_evicted_when_cap_exceeded(self, monkeypatch, auth_app):
        """When sessions > MAX_CONCURRENT_SESSIONS, oldest is auto-revoked."""
        # Use a low cap to test quickly without 5 logins
        from backend.auth import _core as auth_core
        from backend.auth import is_token_revoked
        monkeypatch.setattr(auth_core, "MAX_CONCURRENT_SESSIONS", 2)

        s1 = _login(auth_app)
        jti1 = _decode(s1["access_token"])["jti"]
        s2 = _login(auth_app)
        jti2 = _decode(s2["access_token"])["jti"]
        # At cap (2/2) — neither revoked yet
        assert not is_token_revoked(jti1)
        assert not is_token_revoked(jti2)

        s3 = _login(auth_app)
        jti3 = _decode(s3["access_token"])["jti"]
        # Cap exceeded → oldest (s1) evicted
        assert is_token_revoked(jti1) is True
        assert not is_token_revoked(jti2)
        assert not is_token_revoked(jti3)


# ---------------------------------------------------------------------------
# Bad token paths
# ---------------------------------------------------------------------------

class TestBadTokens:
    def test_no_auth_header_returns_401(self, auth_app):
        resp = auth_app.get("/api/auth/me")
        assert resp.status_code == 401

    def test_garbage_token_returns_401(self, auth_app):
        resp = auth_app.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer this.is.not.a.jwt"},
        )
        assert resp.status_code == 401

    def test_wrong_credentials_returns_401(self, auth_app):
        resp = auth_app.post(
            "/api/auth/login",
            json={"username": "analyst", "password": "WRONG"},
        )
        assert resp.status_code == 401
