# Circuit Breaker — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_circuit_breaker.py`](../../tests/test_circuit_breaker.py)
**Tests**: 12 / 12 passing
**Module**: `backend/connectors/resilience.py`

## Scope

Validates the connector resilience pattern used by every external
integration (Splunk, Sentinel, Elastic, TheHive, Cortex, …):

- CLOSED → OPEN after N consecutive failures
- OPEN rejects calls without invoking the underlying function
- OPEN → HALF_OPEN after `recovery_timeout`
- HALF_OPEN → CLOSED on probe success
- HALF_OPEN → OPEN on probe failure
- HALF_OPEN concurrent probe limit
- success in CLOSED state resets the failure counter
- `@with_retry` decorator: retry success, exhaustion, exception filter

## Test results

```
$ pytest tests/test_circuit_breaker.py -v
tests\test_circuit_breaker.py::TestStateTransitions::test_initial_state_is_closed PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_closed_to_open_after_threshold PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_open_rejects_calls PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_open_to_half_open_after_recovery_timeout PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_half_open_to_closed_on_success PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_half_open_to_open_on_failure PASSED
tests\test_circuit_breaker.py::TestStateTransitions::test_half_open_max_calls_concurrent_probe_rejected PASSED
tests\test_circuit_breaker.py::TestSuccessResetsCounter::test_failure_count_resets_on_success_in_closed PASSED
tests\test_circuit_breaker.py::TestSuccessResetsCounter::test_manual_reset_returns_to_closed PASSED
tests\test_circuit_breaker.py::TestRetryDecorator::test_retries_on_failure_then_succeeds PASSED
tests\test_circuit_breaker.py::TestRetryDecorator::test_exhaustion_raises_last_exception PASSED
tests\test_circuit_breaker.py::TestRetryDecorator::test_only_retryable_exceptions_caught PASSED
============= 12 passed in 1.61s =============
```

## State machine

```
                       (failures < threshold)
                              │
        ┌────────────┐  fail  ▼  fail  ┌──────┐
        │  CLOSED    │ ─────────────► │  OPEN │
        └─────▲──────┘                └───┬──┘
              │ probe ok                  │
              │                           │ recovery_timeout
              │                           ▼
              │                     ┌───────────┐
              └─────────────────────│ HALF_OPEN │
                                    └───────┬───┘
                                            │ probe fails
                                            ▼
                                          OPEN
```

## Key assertions

### OPEN rejects calls without running the function

```python
def test_open_rejects_calls(self):
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
    with pytest.raises(RuntimeError):
        cb.call(_failing_fn)
    assert cb.state is CircuitState.OPEN

    marker = {"called": False}
    def tracker(): marker["called"] = True; return "x"
    with pytest.raises(CircuitOpenError):
        cb.call(tracker)
    assert marker["called"] is False   # PASSES — fn never invoked
```

### Recovery timeout transitions OPEN → HALF_OPEN

```python
def test_open_to_half_open_after_recovery_timeout(self):
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
    with pytest.raises(RuntimeError):
        cb.call(_failing_fn)
    assert cb.state is CircuitState.OPEN

    time.sleep(0.15)
    assert cb.state is CircuitState.HALF_OPEN   # PASSES
```

### Concurrent probe attempts during HALF_OPEN are rejected

```python
def test_half_open_max_calls_concurrent_probe_rejected(self):
    # First thread acquires the only probe slot (slow function)
    # Second thread is rejected with CircuitOpenError → PASSES
```

### Success in CLOSED resets the failure counter

```python
def test_failure_count_resets_on_success_in_closed(self):
    cb = CircuitBreaker(failure_threshold=3)
    fail_twice()
    cb.call(_ok_fn)         # resets counter
    fail_twice_more()       # circuit STILL CLOSED
    assert cb.state is CircuitState.CLOSED   # PASSES
```

## `@with_retry` decorator

| Behaviour | Test |
|---|---|
| Retries on transient failure, succeeds on attempt N | `test_retries_on_failure_then_succeeds` |
| Raises last exception after exhaustion | `test_exhaustion_raises_last_exception` |
| Only catches the configured exception classes | `test_only_retryable_exceptions_caught` |

Default behaviour: 3 retries, exponential backoff factor 2 (1 s, 2 s, 4 s).

## Production usage

Every `BaseConnector` subclass automatically uses a per-connector
circuit breaker (see `backend/connectors/base.py::check_connection`):

```python
class BaseConnector(ABC):
    def __init__(self, ...):
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            name=self.connector_id,
        )

    def check_connection(self) -> dict:
        try:
            return self._circuit_breaker.call(self._raw_check)
        except CircuitOpenError:
            return {"status": "circuit_open", ...}
```

## Threat / failure-mode coverage

| Failure mode | Mitigation | Test |
|---|---|---|
| External service slow / hung | Circuit opens after N timeouts; subsequent calls fail-fast | `test_closed_to_open_after_threshold` |
| Service flapping | HALF_OPEN probe model prevents thundering herd | `test_half_open_max_calls_concurrent_probe_rejected` |
| Transient network glitch | `@with_retry` smooths over single-shot failures | `test_retries_on_failure_then_succeeds` |
| Persistent failure | Retry exhausts and raises; circuit eventually opens | `test_exhaustion_raises_last_exception` |
| Manual operator intervention | `cb.reset()` returns to CLOSED | `test_manual_reset_returns_to_closed` |

## How to reproduce

```bash
pytest tests/test_circuit_breaker.py -v
```

## Limits / next steps

- The current implementation is in-process. For multi-replica
  deployments, the circuit state should ideally be shared via Redis
  (so all replicas trip together) — this is on the v3.3 roadmap.
- The breaker does not currently distinguish between transient
  (timeouts, 5xx) and permanent (4xx, auth) failures. Permanent
  failures should arguably skip the breaker entirely. Roadmap.
- Metric emission (`circuit_state`, `circuit_failures_total`) on
  Prometheus is implemented in `backend/observability/metrics.py`
  but not yet wired to every connector.
