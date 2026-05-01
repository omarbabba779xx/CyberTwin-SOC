"""Production hardening readiness check.

This is intentionally local and deterministic: it validates the environment
and deployment files before a production rollout or disaster-recovery drill.
It does not contact cloud providers or external auditors.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _ok(name: str, detail: str) -> dict:
    return {"check": name, "status": "ok", "detail": detail}


def _fail(name: str, detail: str) -> dict:
    return {"check": name, "status": "fail", "detail": detail}


def run_checks(env: dict[str, str] | None = None) -> dict:
    env = env or os.environ
    checks: list[dict] = []

    jwt_secret = env.get("JWT_SECRET", "")
    checks.append(
        _ok("jwt_secret", "JWT_SECRET length is production-grade")
        if len(jwt_secret) >= 64
        else _fail("jwt_secret", "JWT_SECRET must be at least 64 characters")
    )

    database_url = env.get("DATABASE_URL", "")
    checks.append(
        _ok("database_url", "DATABASE_URL is configured for SQLAlchemy runtime")
        if database_url.startswith(("postgresql://", "postgresql+psycopg2://", "postgresql+asyncpg://"))
        else _fail("database_url", "production requires a PostgreSQL DATABASE_URL")
    )

    redis_url = env.get("REDIS_URL", "")
    checks.append(
        _ok("redis_url", "REDIS_URL is configured")
        if redis_url.startswith(("redis://", "rediss://"))
        else _fail("redis_url", "REDIS_URL should be configured for shared cache/streams")
    )

    cors = [x.strip() for x in env.get("CORS_ORIGINS", "").split(",") if x.strip()]
    checks.append(
        _ok("cors_origins", "CORS origins are explicit")
        if cors and "*" not in cors
        else _fail("cors_origins", "CORS_ORIGINS must be explicit and must not contain *")
    )

    for name in ("AUTH_ADMIN_PASSWORD", "AUTH_ANALYST_PASSWORD", "AUTH_VIEWER_PASSWORD"):
        value = env.get(name, "")
        checks.append(
            _ok(name.lower(), f"{name} is set with >= 16 chars")
            if len(value) >= 16 and not value.startswith("changeme")
            else _fail(name.lower(), f"{name} must be non-default and >= 16 chars")
        )

    required_files = [
        "scripts/backup.sh",
        "docs/operations/backup-recovery.md",
        "docs/proof/production-deployment.md",
        "deploy/helm/cybertwin-soc/values-secure.yaml",
    ]
    for rel in required_files:
        path = ROOT / rel
        checks.append(
            _ok(f"file:{rel}", "present")
            if path.exists()
            else _fail(f"file:{rel}", "missing")
        )

    failed = [item for item in checks if item["status"] != "ok"]
    return {
        "status": "ok" if not failed else "fail",
        "failed": len(failed),
        "total": len(checks),
        "checks": checks,
    }


def main() -> int:
    report = run_checks()
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
