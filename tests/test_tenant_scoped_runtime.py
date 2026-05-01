"""Regression tests for tenant-scoped runtime state."""

from __future__ import annotations

import pytest


def test_history_store_is_tenant_scoped():
    from backend.database import (
        delete_run,
        get_run,
        get_runs_by_scenario,
        init_db,
        save_run,
    )

    init_db()
    result = {
        "total_events": 0,
        "alerts": [],
        "incidents": [],
        "scores": {
            "overall_score": 42,
            "detection_score": 40,
            "coverage_score": 40,
            "response_score": 40,
            "visibility_score": 40,
            "risk_level": "medium",
            "maturity_level": "developing",
        },
    }
    scenario_id = "tenant-scope-regression"
    run_a = save_run(scenario_id, "Tenant Scope", result, tenant_id="tenant-a")
    run_b = save_run(scenario_id, "Tenant Scope", result, tenant_id="tenant-b")
    try:
        assert get_run(run_a, tenant_id="tenant-a") is not None
        assert get_run(run_a, tenant_id="tenant-b") is None

        tenant_a_runs = get_runs_by_scenario(scenario_id, tenant_id="tenant-a")
        tenant_b_runs = get_runs_by_scenario(scenario_id, tenant_id="tenant-b")
        assert {r["id"] for r in tenant_a_runs} == {run_a}
        assert {r["id"] for r in tenant_b_runs} == {run_b}
    finally:
        delete_run(run_a, tenant_id="tenant-a")
        delete_run(run_b, tenant_id="tenant-b")


def test_ingestion_buffer_is_tenant_scoped():
    from backend.ingestion.pipeline import IngestionPipeline

    pipeline = IngestionPipeline(buffer_size=10)
    pipeline.ingest_one({"event_id": "a", "user": "alice", "host": "h1"}, tenant_id="tenant-a")
    pipeline.ingest_one({"event_id": "b", "user": "bob", "host": "h2"}, tenant_id="tenant-b")

    assert pipeline.buffer_size(tenant_id="tenant-a") == 1
    assert pipeline.buffer_size(tenant_id="tenant-b") == 1
    assert pipeline.buffer_size() == 0
    assert pipeline.snapshot(tenant_id="tenant-a")[0]["tenant_id"] == "tenant-a"
    assert pipeline.snapshot(tenant_id="tenant-b")[0]["tenant_id"] == "tenant-b"


def test_results_cache_is_tenant_scoped(client):
    from backend.api.deps import result_cache_key
    from backend.auth import create_token
    from backend.cache import cache

    cache.clear()
    scenario_id = "tenant-cache-regression"
    result = {
        "alerts": [],
        "incidents": [],
        "timeline": [],
        "scores": {"overall_score": 90},
        "mitre_coverage": {},
        "report": {},
        "logs": [],
        "logs_statistics": {},
    }
    cache.set(result_cache_key(scenario_id, "tenant-a"), result, ttl=120)

    token_a = create_token("alice", "analyst", tenant_id="tenant-a")
    token_b = create_token("bob", "analyst", tenant_id="tenant-b")

    ok = client.get(
        f"/api/results/{scenario_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    denied = client.get(
        f"/api/results/{scenario_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert ok.status_code == 200
    assert denied.status_code == 404


def test_websocket_rejects_refresh_token(client):
    from starlette.websockets import WebSocketDisconnect
    from backend.auth import create_refresh_token

    refresh = create_refresh_token("analyst", "analyst", tenant_id="tenant-a")

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/ws/simulate/apt_campaign?token={refresh}"):
            pass

    assert exc.value.code == 4001


def test_require_permission_uses_dynamic_tenant_permissions(monkeypatch):
    from fastapi import HTTPException
    from backend.auth import _core as auth_core

    monkeypatch.setattr(
        auth_core,
        "_lookup_tenant_permissions",
        lambda role, tenant_id: {"case:read"} if tenant_id == "tenant-a" else set(),
    )

    user = {"sub": "alice", "role": "analyst", "tenant_id": "tenant-a"}
    assert auth_core.require_permission("case:read")(user) == user

    with pytest.raises(HTTPException) as exc:
        auth_core.require_permission("case:write")(user)
    assert exc.value.status_code == 403


def test_soc_workflow_is_tenant_scoped():
    from backend.soc import (
        add_comment,
        create_case,
        create_suppression,
        feedback_summary,
        get_case,
        init_soc_tables,
        is_alert_suppressed,
        list_cases,
        list_suppressions,
        record_feedback,
    )
    from backend.soc.database import get_conn

    init_soc_tables()
    conn = get_conn()
    for table in ("case_evidence", "case_comments", "alert_feedback", "soc_cases", "suppressions"):
        conn.execute(f"DELETE FROM {table}")  # nosec B608 - static test table list
    conn.commit()
    conn.close()

    case_a = create_case(title="Tenant A case", created_by="alice", tenant_id="tenant-a")
    case_b = create_case(title="Tenant B case", created_by="bob", tenant_id="tenant-b")

    assert get_case(case_a.case_id, tenant_id="tenant-a") is not None
    assert get_case(case_a.case_id, tenant_id="tenant-b") is None
    assert [case.case_id for case in list_cases(tenant_id="tenant-a")] == [case_a.case_id]
    assert [case.case_id for case in list_cases(tenant_id="tenant-b")] == [case_b.case_id]

    with pytest.raises(ValueError):
        add_comment(case_a.case_id, author="bob", role="analyst", body="cross tenant", tenant_id="tenant-b")

    record_feedback(
        alert_id="alert-a",
        rule_id="rule-a",
        verdict="false_positive",
        analyst="alice",
        role="analyst",
        tenant_id="tenant-a",
    )
    assert feedback_summary(tenant_id="tenant-a")["total_feedback"] == 1
    assert feedback_summary(tenant_id="tenant-b")["total_feedback"] == 0

    suppression = create_suppression(
        scope="rule",
        target="rule-a",
        reason="tenant scoped suppression",
        created_by="alice",
        duration_hours=1,
        tenant_id="tenant-a",
    )
    assert list_suppressions(tenant_id="tenant-a")[0].suppression_id == suppression.suppression_id
    assert list_suppressions(tenant_id="tenant-b") == []
    assert is_alert_suppressed({"rule_id": "rule-a"}, tenant_id="tenant-a")[0] is True
    assert is_alert_suppressed({"rule_id": "rule-a"}, tenant_id="tenant-b")[0] is False
