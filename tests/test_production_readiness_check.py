"""Tests for production readiness validation."""

from __future__ import annotations

from scripts.production_readiness_check import run_checks


def test_production_readiness_passes_with_hardened_env():
    report = run_checks({
        "JWT_SECRET": "a" * 64,
        "DATABASE_URL": "postgresql+psycopg2://user:pass@db:5432/cybertwin",
        "REDIS_URL": "rediss://:pass@redis:6380/0",
        "CORS_ORIGINS": "https://soc.example.com",
        "AUTH_ADMIN_PASSWORD": "correct-horse-battery-staple",
        "AUTH_ANALYST_PASSWORD": "correct-horse-battery-staple",
        "AUTH_VIEWER_PASSWORD": "correct-horse-battery-staple",
    })
    assert report["status"] == "ok"


def test_production_readiness_fails_unsafe_defaults():
    report = run_checks({
        "JWT_SECRET": "short",
        "DATABASE_URL": "sqlite:///./data/cybertwin.db",
        "REDIS_URL": "",
        "CORS_ORIGINS": "*",
        "AUTH_ADMIN_PASSWORD": "changeme-admin",
        "AUTH_ANALYST_PASSWORD": "changeme-analyst",
        "AUTH_VIEWER_PASSWORD": "changeme-viewer",
    })
    assert report["status"] == "fail"
    assert report["failed"] >= 5
