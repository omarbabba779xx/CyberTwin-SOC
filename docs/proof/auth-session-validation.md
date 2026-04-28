# Authentication & Session Validation Report

**Commit**: `224b757`
**Date**: 2026-04-28
**Test file**: [`tests/test_auth_session.py`](../../tests/test_auth_session.py)
**Tests**: 15 / 15 passing
**Modules**: `backend/auth/_core.py`, `backend/api/routes/auth.py`

## Scope

End-to-end validation of the JWT session lifecycle exposed by
`/api/auth/*`:

- access tokens carry a `jti` (JWT ID) claim
- refresh tokens carry a separate `jti` and `type=refresh`
- `/api/auth/logout` adds the access-token jti to a Redis-backed denylist
- subsequent calls with the revoked token return **401 Unauthorized**
- `/api/auth/refresh` issues a new (access, refresh) pair and revokes the old refresh jti (rotation)
- replaying an old refresh token returns **401**
- access tokens cannot be used at the refresh endpoint (type guard)
- `/api/auth/revoke-all` invalidates every active session for the user
- session governance evicts the oldest session when `MAX_CONCURRENT_SESSIONS` is exceeded
- bad tokens / wrong credentials return **401**

## Test results

```
$ pytest tests/test_auth_session.py -v
tests\test_auth_session.py::TestAccessTokenStructure::test_login_returns_access_and_refresh PASSED
tests\test_auth_session.py::TestAccessTokenStructure::test_access_token_contains_jti PASSED
tests\test_auth_session.py::TestAccessTokenStructure::test_refresh_token_contains_jti_and_type PASSED
tests\test_auth_session.py::TestLogoutRevokesJTI::test_token_works_before_logout PASSED
tests\test_auth_session.py::TestLogoutRevokesJTI::test_logout_adds_jti_to_denylist PASSED
tests\test_auth_session.py::TestLogoutRevokesJTI::test_revoked_token_returns_401 PASSED
tests\test_auth_session.py::TestRefreshTokenRotation::test_refresh_returns_new_pair PASSED
tests\test_auth_session.py::TestRefreshTokenRotation::test_old_refresh_jti_is_revoked_after_rotation PASSED
tests\test_auth_session.py::TestRefreshTokenRotation::test_replaying_old_refresh_returns_401 PASSED
tests\test_auth_session.py::TestRefreshTokenRotation::test_access_token_rejected_at_refresh_endpoint PASSED
tests\test_auth_session.py::TestRevokeAllSessions::test_revoke_all_invalidates_all_open_tokens PASSED
tests\test_auth_session.py::TestConcurrentSessionCap::test_oldest_session_evicted_when_cap_exceeded PASSED
tests\test_auth_session.py::TestBadTokens::test_no_auth_header_returns_401 PASSED
tests\test_auth_session.py::TestBadTokens::test_garbage_token_returns_401 PASSED
tests\test_auth_session.py::TestBadTokens::test_wrong_credentials_returns_401 PASSED
============= 15 passed in 6.60s =============
```

## Key assertions

### Access token contains jti

```python
def test_access_token_contains_jti(self, auth_app):
    body = _login(auth_app)            # POST /api/auth/login
    decoded = _decode(body["access_token"])
    assert "jti" in decoded and len(decoded["jti"]) == 32   # 16 hex bytes
    assert decoded["type"] == "access"                       # PASSES
    assert decoded["sub"] == "analyst"
    assert decoded["role"] == "analyst"
```

### Logout adds jti to Redis denylist

```python
def test_logout_adds_jti_to_denylist(self, auth_app):
    body = _login(auth_app)
    jti = _decode(body["access_token"])["jti"]
    assert is_token_revoked(jti) is False                    # before
    auth_app.post("/api/auth/logout",
                  headers={"Authorization": f"Bearer {body['access_token']}"})
    assert is_token_revoked(jti) is True                     # after — PASSES
```

### Revoked token returns 401

```python
def test_revoked_token_returns_401(self, auth_app):
    body = _login(auth_app); token = body["access_token"]
    auth_app.post("/api/auth/logout",
                  headers={"Authorization": f"Bearer {token}"})
    resp = auth_app.get("/api/auth/me",
                         headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401                            # PASSES
    assert "revoked" in resp.json()["detail"].lower()
```

### Refresh token rotation

```python
def test_replaying_old_refresh_returns_401(self, auth_app):
    body = _login(auth_app)
    first = auth_app.post("/api/auth/refresh",
                          json={"refresh_token": body["refresh_token"]})
    assert first.status_code == 200

    # Replay the SAME refresh token — must fail (the old jti is now revoked)
    replay = auth_app.post("/api/auth/refresh",
                           json={"refresh_token": body["refresh_token"]})
    assert replay.status_code == 401                          # PASSES
    assert "revoked" in replay.json()["detail"].lower()
```

### Concurrent-session cap

```python
def test_oldest_session_evicted_when_cap_exceeded(self, monkeypatch, auth_app):
    monkeypatch.setattr(auth_core, "MAX_CONCURRENT_SESSIONS", 2)
    s1 = _login(auth_app); jti1 = _decode(s1["access_token"])["jti"]
    s2 = _login(auth_app); jti2 = _decode(s2["access_token"])["jti"]
    s3 = _login(auth_app); jti3 = _decode(s3["access_token"])["jti"]
    # cap=2, three sessions opened → oldest revoked
    assert is_token_revoked(jti1) is True                     # PASSES
    assert not is_token_revoked(jti2)
    assert not is_token_revoked(jti3)
```

## Threat model coverage

| Threat | Mitigation | Test |
|---|---|---|
| Stolen access token used after logout | `verify_token` checks Redis denylist on every call | `test_revoked_token_returns_401` |
| Stolen refresh token reused (replay) | Refresh-token rotation: each refresh revokes the old jti | `test_replaying_old_refresh_returns_401` |
| Attacker uses an access token at /refresh | Type guard rejects non-`refresh` tokens | `test_access_token_rejected_at_refresh_endpoint` |
| User compromise — revoke everywhere | `/api/auth/revoke-all` revokes every session jti for the user | `test_revoke_all_invalidates_all_open_tokens` |
| Session sprawl (lost / forgotten devices) | `MAX_CONCURRENT_SESSIONS` cap auto-evicts oldest | `test_oldest_session_evicted_when_cap_exceeded` |
| Malformed / forged JWT | Signature verification rejects | `test_garbage_token_returns_401` |
| No credentials | `Depends(verify_token)` returns 401 | `test_no_auth_header_returns_401` |

## Implementation map

| Concern | File:Function |
|---|---|
| `jti` generation | `backend/auth/_core.py::create_token` (16 hex bytes via `secrets.token_hex`) |
| Refresh `jti` | `backend/auth/_core.py::create_refresh_token` |
| Denylist check | `backend/auth/_core.py::verify_token` |
| Denylist write | `backend/auth/_core.py::revoke_token` (Redis `setex` with TTL = remaining token life) |
| Logout endpoint | `backend/api/routes/auth.py::logout` |
| Refresh + rotation | `backend/api/routes/auth.py::refresh_access_token` |
| Revoke-all endpoint | `backend/api/routes/auth.py::revoke_all` → `revoke_all_sessions(username)` |
| Session tracking | `backend/auth/_core.py::track_session` (Redis list keyed by username) |
| Session cap | `MAX_CONCURRENT_SESSIONS` env var (default 5) |
| `verify_token` dep | applied to every protected endpoint via `Depends(verify_token)` |

## How to reproduce

```bash
pytest tests/test_auth_session.py -v
```

## Limits / next steps

- The denylist TTL equals the remaining token expiry; once the token
  would have expired naturally the entry is evicted from Redis. This
  is deliberate (no unbounded growth), but it means an admin who
  rotates JWT_SECRET still needs to wait for the longest-lived token
  to age out before old tokens are guaranteed gone (or set
  JWT_SECRET to a new value, which immediately invalidates everything).
- Refresh-token rotation is per-jti; it does NOT detect token theft
  if the attacker refreshes BEFORE the legitimate user. The roadmap
  includes refresh-token family detection (Auth0-style), where any
  divergence from the chain revokes the entire family.
- The `_USER_STORE` is in-memory and bcrypt-hashed at process start.
  Database-backed users are on the v3.3 backlog (`tenant_users` table).
