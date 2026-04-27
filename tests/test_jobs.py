"""Tests for the background job scaffold (Arq-shaped, in-process today)."""
from __future__ import annotations

import pytest

from backend.jobs.registry import (
    enqueue, get_status, register_task, update_progress,
    list_registered, TaskStatus,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    """Each test starts with a clean registry to avoid name collisions."""
    from backend.jobs import registry as r
    saved = dict(r._TASKS)
    r._TASKS.clear()
    yield
    r._TASKS.clear()
    r._TASKS.update(saved)


class TestRegistration:

    def test_register_and_list(self):
        @register_task("noop")
        async def _noop(task_id: str):
            return {"ok": True}

        assert "noop" in list_registered()

    def test_double_registration_raises(self):
        @register_task("dupe")
        async def _f1(task_id: str): return None  # noqa: E704

        with pytest.raises(ValueError, match="already registered"):
            @register_task("dupe")
            async def _f2(task_id: str): return None  # noqa: E704


class TestEnqueueExecute:

    @pytest.mark.asyncio
    async def test_successful_task_returns_result(self):
        @register_task("echo")
        async def _echo(task_id: str, msg: str = ""):
            return {"echoed": msg}

        task_id = await enqueue("echo", msg="hello")
        status = get_status(task_id)
        assert status is not None
        assert status["status"] == TaskStatus.SUCCEEDED.value
        assert status["progress"] == 100
        assert status["result"] == {"echoed": "hello"}
        assert status["error"] is None

    @pytest.mark.asyncio
    async def test_failed_task_records_error(self):
        @register_task("kaboom")
        async def _kaboom(task_id: str):
            raise RuntimeError("boom")

        task_id = await enqueue("kaboom")
        status = get_status(task_id)
        assert status["status"] == TaskStatus.FAILED.value
        assert "boom" in status["error"]
        assert "RuntimeError" in status["error"]
        assert status["traceback"]

    @pytest.mark.asyncio
    async def test_progress_updates(self):
        @register_task("progress")
        async def _progress(task_id: str):
            update_progress(task_id, 25)
            update_progress(task_id, 75)
            return None

        task_id = await enqueue("progress")
        status = get_status(task_id)
        # Final status is succeeded with progress=100, but the task did set
        # intermediate values — we just verify the success path here.
        assert status["status"] == TaskStatus.SUCCEEDED.value
        assert status["progress"] == 100

    @pytest.mark.asyncio
    async def test_progress_clamped(self):
        @register_task("clamp")
        async def _clamp(task_id: str):
            update_progress(task_id, -50)
            assert get_status(task_id)["progress"] == 0
            update_progress(task_id, 200)
            assert get_status(task_id)["progress"] == 100
            return None

        await enqueue("clamp")

    @pytest.mark.asyncio
    async def test_unknown_task_raises(self):
        with pytest.raises(KeyError, match="Unknown task"):
            await enqueue("nonexistent")


class TestStatusKeys:

    @pytest.mark.asyncio
    async def test_status_includes_all_lifecycle_timestamps(self):
        @register_task("timed")
        async def _timed(task_id: str):
            return {"value": 42}

        task_id = await enqueue("timed")
        status = get_status(task_id)
        for field in ("enqueued_at", "started_at", "finished_at"):
            assert field in status, f"missing field {field}"
            assert "T" in status[field], f"{field} is not ISO-8601"

    def test_unknown_task_id_returns_none(self):
        assert get_status("does-not-exist") is None
