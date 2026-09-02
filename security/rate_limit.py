"""
Fixed-window rate limiting, keyed by whatever the caller passes (source
IP is the expected use here). Built on KeyValueStore.incr() so it works
identically against InMemoryStore (single process, dev/small deployments)
or RedisStore (shared limit across every instance behind a load
balancer) -- see storage/base.py for why that distinction matters.

Fixed-window rather than sliding-window/token-bucket: simpler, one
counter per window instead of a timestamp log, and "someone can burst up
to 2x the limit right at a window boundary" is a completely acceptable
tradeoff for protecting a webhook endpoint against a misbehaving or
compromised relay -- this isn't billing-grade metering.
"""
from __future__ import annotations

from storage.base import KeyValueStore


class RateLimitExceeded(Exception):
    def __init__(self, key: str, limit: int, window_seconds: int):
        self.key = key
        self.limit = limit
        self.window_seconds = window_seconds
        super().__init__(f"rate limit exceeded for {key!r}: {limit} requests / {window_seconds}s")


class RateLimiter:
    def __init__(self, store: KeyValueStore, max_requests: int, window_seconds: int, key_prefix: str = "ratelimit"):
        self.store = store
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix

    async def check(self, identifier: str) -> None:
        """Raises RateLimitExceeded if `identifier` (e.g. a source IP) has
        exceeded the configured limit for the current window. Otherwise
        records this call and returns normally."""
        key = f"{self.key_prefix}:{identifier}"
        current = await self.store.incr(key, ttl_seconds=self.window_seconds)
        if current > self.max_requests:
            raise RateLimitExceeded(identifier, self.max_requests, self.window_seconds)
