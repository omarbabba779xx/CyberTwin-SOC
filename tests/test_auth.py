"""
Tests for backend/auth.py — password hashing, JWT, RBAC, user store.
"""
import os
import pytest
import jwt


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        from backend.auth import hash_password
        h = hash_password("secret")
        assert h != "secret"
        assert h.startswith("$2b$")

    def test_verify_correct_password(self):
        from backend.auth import hash_password, verify_password
        h = hash_password("mypassword")
        assert verify_password("mypassword", h) is True

    def test_verify_wrong_password(self):
        from backend.auth import hash_password, verify_password
        h = hash_password("correct")
        assert verify_password("wrong", h) is False

    def test_two_hashes_are_different(self):
        from backend.auth import hash_password
        assert hash_password("same") != hash_password("same")

    def test_verify_invalid_hash_returns_false(self):
        from backend.auth import verify_password
        assert verify_password("anything", "not-a-bcrypt-hash") is False


# ---------------------------------------------------------------------------
# JWT creation and verification
# ---------------------------------------------------------------------------

class TestJWT:
    def test_create_token_returns_string(self):
        from backend.auth import create_token
        token = create_token("alice", "analyst")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_token_payload_contains_expected_fields(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM
        token = create_token("alice", "analyst")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "alice"
        assert payload["role"] == "analyst"
        assert "permissions" in payload
        assert "exp" in payload
        assert "iat" in payload

    def test_admin_token_has_all_permissions(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM, ROLES
        token = create_token("admin", "admin")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert set(payload["permissions"]) == ROLES["admin"]

    def test_unknown_role_defaults_to_viewer(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM, ROLES
        token = create_token("ghost", "superuser")
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        assert payload["role"] == "viewer"
        assert set(payload["permissions"]) == ROLES["viewer"]

    def test_expired_token_raises(self):
        from backend.auth import JWT_SECRET, JWT_ALGORITHM
        from datetime import datetime, timedelta
        payload = {
            "sub": "alice", "role": "viewer", "permissions": [],
            "iat": datetime.utcnow() - timedelta(hours=48),
            "exp": datetime.utcnow() - timedelta(hours=24),
        }
        expired = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(expired, JWT_SECRET, algorithms=[JWT_ALGORITHM])

    def test_tampered_token_raises(self):
        from backend.auth import create_token, JWT_SECRET, JWT_ALGORITHM
        token = create_token("alice", "analyst") + "tampered"
        with pytest.raises(jwt.InvalidTokenError):
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

    def test_wrong_secret_raises(self):
        from backend.auth import create_token, JWT_ALGORITHM
        token = create_token("alice", "analyst")
        with pytest.raises(jwt.InvalidTokenError):
            jwt.decode(token, "wrong-secret", algorithms=[JWT_ALGORITHM])


# ---------------------------------------------------------------------------
# RBAC — has_permission
# ---------------------------------------------------------------------------

class TestRBAC:
    def test_admin_has_all_permissions(self):
        from backend.auth import has_permission
        for perm in ["run_simulation", "view_audit_log", "manage_users", "delete_history"]:
            assert has_permission("admin", perm) is True

    def test_analyst_can_run_simulation(self):
        from backend.auth import has_permission
        assert has_permission("analyst", "run_simulation") is True

    def test_analyst_cannot_view_audit_log(self):
        from backend.auth import has_permission
        assert has_permission("analyst", "view_audit_log") is False

    def test_viewer_can_view_results(self):
        from backend.auth import has_permission
        assert has_permission("viewer", "view_results") is True

    def test_production_safety_requires_postgres_database_url(self, monkeypatch):
        from backend.auth import check_production_safety

        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("JWT_SECRET", "x" * 64)
        monkeypatch.setenv("AUTH_ADMIN_PASSWORD", "correct-horse-battery-staple")
        monkeypatch.setenv("AUTH_ANALYST_PASSWORD", "correct-horse-battery-staple")
        monkeypatch.setenv("AUTH_VIEWER_PASSWORD", "correct-horse-battery-staple")

        monkeypatch.delenv("DATABASE_URL", raising=False)
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            check_production_safety()

        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://user:pass@db:5432/cybertwin")
        check_production_safety()

    def test_viewer_cannot_run_simulation(self):
        from backend.auth import has_permission
        assert has_permission("viewer", "run_simulation") is False

    def test_unknown_role_has_no_permissions(self):
        from backend.auth import has_permission
        assert has_permission("hacker", "run_simulation") is False

    def test_roles_are_hierarchical(self):
        from backend.auth import ROLES
        assert ROLES["admin"] > ROLES["analyst"]
        assert ROLES["analyst"] > ROLES["viewer"]


# ---------------------------------------------------------------------------
# User store — authenticate_user
# ---------------------------------------------------------------------------

class TestAuthenticateUser:
    def test_valid_admin_credentials(self):
        from backend.auth import authenticate_user
        user = authenticate_user("admin", os.getenv("AUTH_ADMIN_PASSWORD", "admin-test-123"))
        assert user is not None
        assert user["username"] == "admin"
        assert user["role"] == "admin"

    def test_valid_analyst_credentials(self):
        from backend.auth import authenticate_user
        user = authenticate_user("analyst", os.getenv("AUTH_ANALYST_PASSWORD", "analyst-test-123"))
        assert user is not None
        assert user["role"] == "analyst"

    def test_wrong_password_returns_none(self):
        from backend.auth import authenticate_user
        assert authenticate_user("admin", "wrong-password") is None

    def test_unknown_user_returns_none(self):
        from backend.auth import authenticate_user
        assert authenticate_user("nobody", "whatever") is None

    def test_empty_credentials_return_none(self):
        from backend.auth import authenticate_user
        assert authenticate_user("", "") is None
