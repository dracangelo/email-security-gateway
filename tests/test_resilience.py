import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from resilience.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from resilience.retry import RetryExhausted, with_retry


def _run(coro):
    return asyncio.run(coro)


class TestRetry:
    def test_succeeds_first_try_no_delay(self):
        calls = []

        @with_retry(max_attempts=3, base_delay=0.01)
        async def flaky():
            calls.append(1)
            return "ok"

        assert _run(flaky()) == "ok"
        assert len(calls) == 1

    def test_succeeds_after_transient_failures(self):
        attempts = {"n": 0}

        @with_retry(max_attempts=5, base_delay=0.01, max_delay=0.02)
        async def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionError("transient")
            return "ok"

        assert _run(flaky()) == "ok"
        assert attempts["n"] == 3

    def test_exhausts_and_raises_retry_exhausted(self):
        @with_retry(max_attempts=3, base_delay=0.01, max_delay=0.02)
        async def always_fails():
            raise ConnectionError("nope")

        with pytest.raises(RetryExhausted) as exc_info:
            _run(always_fails())
        assert exc_info.value.attempts == 3
        assert isinstance(exc_info.value.last_exception, ConnectionError)

    def test_only_retries_specified_exceptions(self):
        @with_retry(max_attempts=3, base_delay=0.01, retry_on=(ConnectionError,))
        async def raises_value_error():
            raise ValueError("not retryable")

        with pytest.raises(ValueError):
            _run(raises_value_error())

    def test_backoff_actually_delays(self):
        attempts = {"n": 0}
        timestamps = []

        @with_retry(max_attempts=3, base_delay=0.1, max_delay=1.0)
        async def flaky():
            timestamps.append(time.monotonic())
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionError("transient")
            return "ok"

        _run(flaky())
        # each gap should be at least base_delay (before jitter is added)
        assert timestamps[1] - timestamps[0] >= 0.1
        assert timestamps[2] - timestamps[1] >= 0.1


class TestCircuitBreaker:
    def test_closed_allows_calls_through(self):
        breaker = CircuitBreaker("test", failure_threshold=3, reset_timeout=1)

        async def ok():
            return "result"

        assert _run(breaker.call(ok)) == "result"
        assert breaker.state == CircuitState.CLOSED

    def test_opens_after_threshold_failures(self):
        breaker = CircuitBreaker("test", failure_threshold=3, reset_timeout=10)

        async def fails():
            raise RuntimeError("boom")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                _run(breaker.call(fails))

        assert breaker.state == CircuitState.OPEN

    def test_open_circuit_fails_fast_without_calling(self):
        breaker = CircuitBreaker("test", failure_threshold=1, reset_timeout=10)
        calls = {"n": 0}

        async def fails():
            calls["n"] += 1
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            _run(breaker.call(fails))
        assert calls["n"] == 1

        # circuit is now open -- next call should NOT invoke fails() at all
        with pytest.raises(CircuitOpenError):
            _run(breaker.call(fails))
        assert calls["n"] == 1  # unchanged

    def test_half_open_success_closes_circuit(self):
        breaker = CircuitBreaker("test", failure_threshold=1, reset_timeout=0.2)

        async def fails():
            raise RuntimeError("boom")

        async def succeeds():
            return "ok"

        with pytest.raises(RuntimeError):
            _run(breaker.call(fails))
        assert breaker.state == CircuitState.OPEN

        time.sleep(0.3)  # let reset_timeout elapse
        assert breaker.state == CircuitState.HALF_OPEN

        result = _run(breaker.call(succeeds))
        assert result == "ok"
        assert breaker.state == CircuitState.CLOSED

    def test_half_open_failure_reopens_circuit(self):
        breaker = CircuitBreaker("test", failure_threshold=1, reset_timeout=0.2)

        async def fails():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            _run(breaker.call(fails))
        time.sleep(0.3)
        assert breaker.state == CircuitState.HALF_OPEN

        with pytest.raises(RuntimeError):
            _run(breaker.call(fails))
        assert breaker.state == CircuitState.OPEN
