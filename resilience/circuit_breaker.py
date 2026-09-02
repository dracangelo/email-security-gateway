"""
Circuit breaker: after `failure_threshold` consecutive failures, stop
calling the wrapped function for `reset_timeout` seconds and fail fast
instead. Without this, a dead reputation API doesn't just fail its own
lookups -- every message waits out the full retry-with-backoff cycle
(seconds) on every single URL, and under load that latency compounds
into the whole gateway backing up behind a provider that isn't coming
back anytime soon.

Three states, standard circuit-breaker model:
  CLOSED     -- normal operation, calls go through.
  OPEN       -- tripped; calls fail immediately with CircuitOpenError
                until reset_timeout elapses.
  HALF_OPEN  -- one trial call is let through after the timeout; success
                closes the circuit again, failure re-opens it.

In-memory and per-process by design, same reasoning as InMemoryStore: if
you run multiple gateway instances, each tracks its own upstream health
independently, which is actually fine here (unlike rate limiting) since
"is VirusTotal down" isn't a value that needs to be consistent across
instances -- each one just needs to stop hurting itself.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Callable, TypeVar

T = TypeVar("T")


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    def __init__(self, name: str, retry_after: float):
        self.name = name
        self.retry_after = retry_after
        super().__init__(f"circuit '{name}' is open, retry after {retry_after:.1f}s")


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5, reset_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            if time.monotonic() - self._opened_at >= self.reset_timeout:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._state = CircuitState.CLOSED
        self._opened_at = None

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_at = time.monotonic()

    async def call(self, func: Callable[[], "T"]) -> T:
        current_state = self.state
        if current_state == CircuitState.OPEN:
            retry_after = self.reset_timeout - (time.monotonic() - (self._opened_at or 0))
            raise CircuitOpenError(self.name, max(0, retry_after))

        try:
            result = await func()
        except Exception:
            self._record_failure()
            raise
        else:
            self._record_success()
            return result
