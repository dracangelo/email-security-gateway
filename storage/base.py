"""
One small KV interface, three unrelated-looking uses: DNS/reputation
result caching, webhook idempotency (dedup on retry), and rate-limit
counters. All three are "store a value, maybe with a TTL, maybe atomically
increment it" -- no reason to build three separate abstractions.

Two implementations:
  - InMemoryStore: zero setup, correct for a single process. This is what
    you get by default. Fine for local dev and small single-instance
    deployments.
  - RedisStore: shared across processes/instances. Use this the moment you
    run more than one gateway worker -- an in-memory rate limiter or
    idempotency cache is per-process, so with N workers behind a load
    balancer each one enforces its own separate limit/cache, which isn't
    actually protecting anything as a whole.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class KeyValueStore(ABC):
    @abstractmethod
    async def get(self, key: str) -> str | None:
        """Returns the stored value, or None if missing/expired."""

    @abstractmethod
    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Stores a value, optionally with a TTL after which it expires."""

    @abstractmethod
    async def set_if_not_exists(self, key: str, value: str, ttl_seconds: int | None = None) -> bool:
        """Atomic "only set if absent". Returns True if this call set the
        value (key was absent), False if the key already existed. This is
        the primitive idempotency and distributed locking are built on --
        without atomicity, two concurrent requests can both see "not
        present" and both proceed, which defeats the point."""

    @abstractmethod
    async def incr(self, key: str, ttl_seconds: int | None = None) -> int:
        """Atomically increments a counter (creating it at 0 first if
        absent) and returns the new value. ttl_seconds is only applied
        when the key is created, matching Redis's INCR+EXPIRE pattern for
        fixed-window rate limiting."""

    @abstractmethod
    async def delete(self, key: str) -> None:
        ...
