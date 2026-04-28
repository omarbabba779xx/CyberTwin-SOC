"""Circuit breaker and retry logic for external connector calls."""

from __future__ import annotations

import enum
import functools
import logging
import threading
import time
from typing import Any, Callable, TypeVar

from .base import ConnectorError

logger = logging.getLogger("cybertwin.connectors.resilience")
F = TypeVar("F", bound=Callable[..., Any])


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(ConnectorError):
    """Raised when a call is attempted while the circuit breaker is open."""


class CircuitBreaker:
    """Thread-safe circuit breaker for external service calls.

    State machine:
        CLOSED  → (failures >= threshold)  → OPEN
        OPEN    → (recovery_timeout elapsed) → HALF_OPEN
        HALF_OPEN → (probe succeeds) → CLOSED
        HALF_OPEN → (probe fails)    → OPEN
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
        name: str = "default",
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state is CircuitState.OPEN:
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info("Circuit %s transitioning OPEN → HALF_OPEN", self.name)
            return self._state

    def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute *fn* guarded by the circuit breaker.

        Raises ``CircuitOpenError`` if the circuit is open and the
        recovery timeout has not yet elapsed.
        """
        current = self.state

        if current is CircuitState.OPEN:
            raise CircuitOpenError(
                f"Circuit breaker '{self.name}' is OPEN — call rejected"
            )

        if current is CircuitState.HALF_OPEN:
            with self._lock:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitOpenError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN — "
                        f"max probe calls ({self.half_open_max_calls}) reached"
                    )
                self._half_open_calls += 1

        try:
            result = fn(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise
        else:
            self._record_success()
            return result

    def _record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state is CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning("Circuit %s HALF_OPEN → OPEN (probe failed)", self.name)
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "Circuit %s CLOSED → OPEN after %d failures",
                    self.name, self._failure_count,
                )

    def _record_success(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                logger.info("Circuit %s HALF_OPEN → CLOSED (probe succeeded)", self.name)
            elif self._state is CircuitState.CLOSED:
                self._failure_count = 0

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0
            logger.info("Circuit %s manually reset to CLOSED", self.name)


def with_retry(
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[F], F]:
    """Decorator that retries the wrapped function with exponential backoff.

    Example::

        @with_retry(max_retries=3, backoff_factor=2)
        def fetch_data():
            ...
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: BaseException | None = None
            for attempt in range(max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exc = exc
                    if attempt < max_retries:
                        delay = backoff_factor ** attempt
                        logger.warning(
                            "%s attempt %d/%d failed (%s), retrying in %.1fs",
                            fn.__qualname__, attempt + 1, max_retries + 1,
                            exc, delay,
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "%s failed after %d attempts: %s",
                            fn.__qualname__, max_retries + 1, exc,
                        )
            raise last_exc  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    return decorator
