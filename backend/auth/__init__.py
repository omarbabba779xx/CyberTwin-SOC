"""CyberTwin SOC — Authentication & RBAC package.

Re-exports every public name from the original ``backend.auth`` module
(now ``backend.auth._core``) so that all existing imports continue to
work without any changes.
"""

from backend.auth._core import (  # noqa: F401
    # Password hashing
    hash_password,
    verify_password,
    # JWT config
    JWT_SECRET,
    JWT_ALGORITHM,
    JWT_EXPIRY_HOURS,
    REFRESH_EXPIRY_DAYS,
    # Roles & permissions
    PERMISSIONS_SCOPED,
    PERMISSIONS_LEGACY,
    ROLES,
    has_permission,
    # Token lifecycle
    security,
    create_token,
    create_refresh_token,
    revoke_token,
    revoke_all_sessions,
    is_token_revoked,
    verify_token,
    verify_token_optional,
    require_permission,
    # User store
    authenticate_user,
    # Production safety
    check_production_safety,
    # Internal helpers used by tests
    _all_perms,
    _build_user_store,
)

# Make dir() / help() useful
__all__ = [
    "hash_password", "verify_password",
    "JWT_SECRET", "JWT_ALGORITHM", "JWT_EXPIRY_HOURS", "REFRESH_EXPIRY_DAYS",
    "PERMISSIONS_SCOPED", "PERMISSIONS_LEGACY", "ROLES", "has_permission",
    "security", "create_token", "create_refresh_token",
    "revoke_token", "revoke_all_sessions", "is_token_revoked",
    "verify_token", "verify_token_optional", "require_permission",
    "authenticate_user", "check_production_safety",
]
