"""
Redis-backed KV store -- use this once you run more than one gateway
process/instance. Uses redis.asyncio so it doesn't block the event loop
that's also handling inbound webhook requests.
"""
from __future__ import annotations

import redis.asyncio as aioredis

from .base import KeyValueStore


class RedisStore(KeyValueStore):
    def __init__(self, redis_url: str = "redis://localhost:6379/0", client: aioredis.Redis | None = None):
        self._client = client or aioredis.from_url(redis_url, decode_responses=True)

    async def get(self, key: str) -> str | None:
        return await self._client.get(key)

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        await self._client.set(key, value, ex=ttl_seconds)

    async def set_if_not_exists(self, key: str, value: str, ttl_seconds: int | None = None) -> bool:
        # NX is Redis's native "set only if absent" -- already atomic, no script needed.
        result = await self._client.set(key, value, nx=True, ex=ttl_seconds)
        return result is True

    async def incr(self, key: str, ttl_seconds: int | None = None) -> int:
        # INCR itself is atomic -- only the caller that actually creates the
        # key (return value == 1) attaches the TTL. There's a small window
        # between that INCR and the EXPIRE call where the key exists without
        # a TTL (if the process died in between, the key would live forever
        # instead of expiring). A Lua script (EVAL) would close that window,
        # but real deployments often run Redis behind proxies/managed
        # services that restrict scripting, and it's untestable against
        # fakeredis -- for a rate-limit counter, "extremely rare permanent
        # key" is an acceptable tradeoff against that operational cost.
        # Revisit with a Lua script if this ever backs something where that
        # gap actually matters.
        new_value = await self._client.incr(key)
        if new_value == 1 and ttl_seconds:
            await self._client.expire(key, ttl_seconds)
        return int(new_value)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def close(self) -> None:
        await self._client.aclose()

    async def ping(self) -> bool:
        """For health checks -- returns False instead of raising on any failure."""
        try:
            return bool(await self._client.ping())
        except Exception:
            return False

