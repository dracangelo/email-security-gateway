"""
Retry decorator for the external calls in this codebase (RDAP, VirusTotal,
Safe Browsing, and DNS resolution). Hand-rolled instead of pulling in
tenacity -- the actual need here is small (exponential backoff + jitter,
a max attempt count, and a way to say "don't retry this exception") and
not worth a new dependency for.

Jitter matters more than it looks: without it, a burst of messages that
all hit a transient failure at the same moment (e.g. your DNS resolver
blips) retry in lockstep, turning one brief outage into a synchronized
thundering-herd retry storm against the same upstream that just recovered.
"""
from __future__ import annotations

import asyncio
import functools
import random
from typing import Callable, TypeVar

T = TypeVar("T")


class RetryExhausted(Exception):
    """Raised when all attempts fail; wraps the last underlying exception."""

    def __init__(self, attempts: int, last_exception: Exception):
        self.attempts = attempts
        self.last_exception = last_exception
        super().__init__(f"gave up after {attempts} attempts: {last_exception!r}")


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 0.25,
    max_delay: float = 5.0,
    retry_on: tuple[type[Exception], ...] = (Exception,),
):
    """
    Decorator for async functions. Retries on any exception in `retry_on`
    with exponential backoff (base_delay * 2**attempt) capped at
    max_delay, plus up to 50% random jitter. Re-raises RetryExhausted
    after the last attempt rather than swallowing the failure -- callers
    (typically a provider wrapped in a circuit breaker) decide what
    "give up" means for them, this decorator's only job is "did the call
    eventually succeed."
    """

    def decorator(func: Callable[..., "asyncio.Future[T]"]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception: Exception | None = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except retry_on as exc:  # noqa: PERF203 -- clarity over micro-optimization here
                    last_exception = exc
                    if attempt == max_attempts - 1:
                        break
                    delay = min(base_delay * (2**attempt), max_delay)
                    delay += random.uniform(0, delay * 0.5)
                    await asyncio.sleep(delay)
            raise RetryExhausted(max_attempts, last_exception)

        return wrapper

    return decorator
