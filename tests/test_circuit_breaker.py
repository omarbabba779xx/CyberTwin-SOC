"""Integration tests for the connector circuit breaker.

Verifies:
- CLOSED → OPEN transition after threshold failures
- OPEN → HALF_OPEN after recovery timeout
- HALF_OPEN → CLOSED after successful probe
- HALF_OPEN → OPEN after failed probe
- failure count resets on success
- thread-safety under concurrent calls
- @with_retry decorator: success after retries, exhaustion behaviour
"""
from __future__ import annotations

import threading
import time

import pytest

from backend.connectors.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    with_retry,
)


def _failing_fn(*_a, **_kw):
    raise RuntimeError("simulated failure")


def _ok_fn(*_a, **_kw):
    return "ok"


class TestStateTransitions:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(name="test")
        assert cb.state is CircuitState.CLOSED

    def test_closed_to_open_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60, name="test")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(_failing_fn)
        assert cb.state is CircuitState.CLOSED

        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.OPEN

    def test_open_rejects_calls(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60, name="test")
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.OPEN

        # Now any call must be rejected immediately without invoking fn
        marker = {"called": False}

        def tracker():
            marker["called"] = True
            return "should-not-run"

        with pytest.raises(CircuitOpenError):
            cb.call(tracker)
        assert marker["called"] is False

    def test_open_to_half_open_after_recovery_timeout(self):
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,  # 100 ms for fast test
            name="test",
        )
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.OPEN

        time.sleep(0.15)
        assert cb.state is CircuitState.HALF_OPEN

    def test_half_open_to_closed_on_success(self):
        cb = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.1, name="test"
        )
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        time.sleep(0.15)

        result = cb.call(_ok_fn)
        assert result == "ok"
        assert cb.state is CircuitState.CLOSED

    def test_half_open_to_open_on_failure(self):
        cb = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.1, name="test"
        )
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        time.sleep(0.15)
        assert cb.state is CircuitState.HALF_OPEN

        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.OPEN

    def test_half_open_max_calls_concurrent_probe_rejected(self):
        """Concurrent probe attempts during HALF_OPEN must be rejected past the limit."""
        cb = CircuitBreaker(
            failure_threshold=1,
            recovery_timeout=0.1,
            half_open_max_calls=1,
            name="test",
        )
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        time.sleep(0.15)
        assert cb.state is CircuitState.HALF_OPEN

        gate = threading.Event()
        results = {"first": None, "second": None}

        def slow_probe():
            gate.wait(timeout=2)
            return "ok"

        def first_caller():
            try:
                results["first"] = cb.call(slow_probe)
            except Exception as e:
                results["first"] = type(e).__name__

        t = threading.Thread(target=first_caller)
        t.start()
        time.sleep(0.05)  # let first thread acquire half_open slot

        try:
            cb.call(_ok_fn)
            results["second"] = "succeeded"
        except CircuitOpenError:
            results["second"] = "rejected"

        gate.set()
        t.join(timeout=2)
        assert results["second"] == "rejected"


class TestSuccessResetsCounter:
    def test_failure_count_resets_on_success_in_closed(self):
        cb = CircuitBreaker(failure_threshold=3, name="test")
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.CLOSED

        cb.call(_ok_fn)

        # Two more failures should not open the circuit (counter was reset)
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.CLOSED

    def test_manual_reset_returns_to_closed(self):
        cb = CircuitBreaker(failure_threshold=1, name="test")
        with pytest.raises(RuntimeError):
            cb.call(_failing_fn)
        assert cb.state is CircuitState.OPEN
        cb.reset()
        assert cb.state is CircuitState.CLOSED


class TestRetryDecorator:
    def test_retries_on_failure_then_succeeds(self):
        attempts = {"n": 0}

        @with_retry(max_retries=3, backoff_factor=0)
        def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise RuntimeError("flake")
            return "done"

        assert flaky() == "done"
        assert attempts["n"] == 3

    def test_exhaustion_raises_last_exception(self):
        @with_retry(max_retries=2, backoff_factor=0)
        def always_fails():
            raise ValueError("permanent")

        with pytest.raises(ValueError, match="permanent"):
            always_fails()

    def test_only_retryable_exceptions_caught(self):
        attempts = {"n": 0}

        @with_retry(
            max_retries=3,
            backoff_factor=0,
            retryable_exceptions=(RuntimeError,),
        )
        def selective():
            attempts["n"] += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError):
            selective()
        assert attempts["n"] == 1
