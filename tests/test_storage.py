import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import fakeredis.aioredis
import pytest

from storage.memory import InMemoryStore
from storage.redis_store import RedisStore


def _run(coro):
    return asyncio.run(coro)


def _redis_store() -> RedisStore:
    fake_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisStore(client=fake_client)


# Run every test against both backends -- they must behave identically,
# that's the entire point of the abstraction.
@pytest.fixture(params=["memory", "redis"])
def store(request):
    return InMemoryStore() if request.param == "memory" else _redis_store()


class TestKeyValueStore:
    def test_get_missing_returns_none(self, store):
        assert _run(store.get("nope")) is None

    def test_set_then_get(self, store):
        _run(store.set("k", "v"))
        assert _run(store.get("k")) == "v"

    def test_delete(self, store):
        _run(store.set("k", "v"))
        _run(store.delete("k"))
        assert _run(store.get("k")) is None

    def test_ttl_expiry(self, store):
        async def scenario():
            await store.set("k", "v", ttl_seconds=1)
            assert await store.get("k") == "v"
            await asyncio.sleep(1.3)
            assert await store.get("k") is None

        _run(scenario())

    def test_set_if_not_exists_first_call_wins(self, store):
        async def scenario():
            first = await store.set_if_not_exists("k", "a")
            second = await store.set_if_not_exists("k", "b")
            return first, second, await store.get("k")

        first, second, value = _run(scenario())
        assert first is True
        assert second is False
        assert value == "a"  # second call did NOT overwrite

    def test_incr_creates_and_increments(self, store):
        async def scenario():
            a = await store.incr("counter")
            b = await store.incr("counter")
            c = await store.incr("counter")
            return a, b, c

        assert _run(scenario()) == (1, 2, 3)

    def test_incr_respects_ttl_on_creation_only(self, store):
        async def scenario():
            await store.incr("counter", ttl_seconds=10)
            await store.incr("counter", ttl_seconds=10)  # should NOT reset the window
            return await store.get("counter")

        assert _run(scenario()) == "2"
