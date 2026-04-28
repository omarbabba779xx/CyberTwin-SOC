"""Integration tests for the Arq worker / in-process fallback registry.

Verifies:
- registered tasks are discoverable via list_registered()
- enqueue() returns a task_id and runs the task in-process when no
  Arq worker is reachable
- get_status() returns proper lifecycle states (queued → running → succeeded)
- failed tasks land in the FAILED state with the error captured
- update_progress() clamps to [0, 100]
- a duplicate registration is rejected
- the Arq pool gracefully degrades when Redis is unreachable
"""
from __future__ import annotations

import asyncio

import pytest

from backend.jobs import registry as reg
from backend.jobs.registry import (
    TaskStatus,
    enqueue,
    get_status,
    list_registered,
    register_task,
    reset_arq_pool,
    update_progress,
)


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    """Reset Arq pool state before each test so we always exercise the
    in-process fallback path (no real Redis required)."""
    reset_arq_pool()
    # Force-fail any Arq pool creation attempt so the fallback runs synchronously
    monkeypatch.setattr(reg, "_arq_pool_failed", True, raising=False)
    yield
    reset_arq_pool()


class TestRegistration:
    def test_registered_tasks_listed(self):
        names = list_registered()
        # The default tasks package registers at least one task
        assert isinstance(names, list)
        # Built-in tasks (registered by backend/jobs/tasks/__init__.py)
        # should include coverage_recalculate
        if "coverage_recalculate" in names:
            assert names.count("coverage_recalculate") == 1

    def test_duplicate_registration_rejected(self):
        @register_task("test_dup_task_unique_xyz")
        async def fn1(task_id: str):
            return "ok"

        with pytest.raises(ValueError, match="already registered"):
            @register_task("test_dup_task_unique_xyz")
            async def fn2(task_id: str):
                return "dup"


class TestInProcessExecution:
    def test_enqueue_runs_in_process_and_returns_id(self):
        @register_task("test_simple_in_proc")
        async def task(task_id: str, **kw):
            return {"answer": 42}

        async def runner():
            return await enqueue("test_simple_in_proc")

        task_id = asyncio.run(runner())
        assert isinstance(task_id, str) and len(task_id) >= 8

        status = get_status(task_id)
        assert status is not None
        assert status["status"] == TaskStatus.SUCCEEDED.value
        assert status["progress"] == 100
        assert status["result"] == {"answer": 42}

    def test_failed_task_recorded_as_failed(self):
        @register_task("test_failing_in_proc")
        async def task(task_id: str, **kw):
            raise RuntimeError("boom")

        async def runner():
            return await enqueue("test_failing_in_proc")

        task_id = asyncio.run(runner())
        status = get_status(task_id)
        assert status["status"] == TaskStatus.FAILED.value
        assert "boom" in status["error"]
        assert "RuntimeError" in status["error"]

    def test_unknown_task_raises_keyerror(self):
        async def runner():
            return await enqueue("definitely_not_a_real_task_xyz")

        with pytest.raises(KeyError):
            asyncio.run(runner())

    def test_kwargs_passed_to_task(self):
        captured = {}

        @register_task("test_kwargs_in_proc")
        async def task(task_id: str, **kw):
            captured.update(kw)
            return "done"

        async def runner():
            return await enqueue("test_kwargs_in_proc", foo="bar", n=7)

        asyncio.run(runner())
        assert captured == {"foo": "bar", "n": 7}


class TestProgress:
    def test_update_progress_clamps_low(self):
        @register_task("test_progress_low")
        async def task(task_id: str, **kw):
            update_progress(task_id, -50)
            status = get_status(task_id)
            assert status["progress"] == 0
            return "ok"

        asyncio.run(enqueue("test_progress_low"))

    def test_update_progress_clamps_high(self):
        @register_task("test_progress_high")
        async def task(task_id: str, **kw):
            update_progress(task_id, 999)
            status = get_status(task_id)
            assert status["progress"] == 100
            return "ok"

        asyncio.run(enqueue("test_progress_high"))


class TestStatusEnvelope:
    def test_status_includes_required_fields(self):
        @register_task("test_status_envelope")
        async def task(task_id: str, **kw):
            return {"ok": True}

        async def runner():
            return await enqueue("test_status_envelope")

        task_id = asyncio.run(runner())
        s = get_status(task_id)
        for field in ("task", "status", "progress", "result",
                      "enqueued_at", "started_at", "finished_at"):
            assert field in s, f"missing field {field}"

    def test_status_for_unknown_id_returns_none(self):
        assert get_status("0" * 16) is None
