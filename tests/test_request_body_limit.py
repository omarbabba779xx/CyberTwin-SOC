"""Validate the per-request body cap (16 MiB by default).

Replaces the previous documentation claim that uvicorn enforced this via
`--limit-max-body-size` (uvicorn has no such CLI flag). The cap is now
enforced by `MaxBodySizeMiddleware` in `backend.api.main`.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.api.main import app, MAX_BODY_BYTES


def _client() -> TestClient:
    return TestClient(app)


def test_default_body_cap_is_16_mib():
    assert MAX_BODY_BYTES == 16 * 1024 * 1024


def test_request_under_cap_is_accepted():
    payload_size = 1024
    body = b"x" * payload_size
    response = _client().post(
        "/api/auth/login",
        content=body,
        headers={"Content-Length": str(payload_size), "Content-Type": "application/json"},
    )
    assert response.status_code != 413


def test_request_over_cap_is_rejected_with_413():
    oversized = MAX_BODY_BYTES + 1
    response = _client().post(
        "/api/ingest/event",
        content=b"",
        headers={
            "Content-Length": str(oversized),
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 413
    body = response.json()
    assert body.get("error", {}).get("code") == "REQUEST_ENTITY_TOO_LARGE"


def test_invalid_content_length_is_rejected_with_400():
    response = _client().post(
        "/api/ingest/event",
        content=b"",
        headers={
            "Content-Length": "not-a-number",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 400
    body = response.json()
    assert body.get("error", {}).get("code") == "BAD_REQUEST"
