"""Single-process KV store. See base.py for why this exists and its limits."""
from __future__ import annotations

import asyncio
import time

from .base import KeyValueStore


class InMemoryStore(KeyValueStore):
    def __init__(self):
        self._data: dict[str, tuple[str, float | None]] = {}  # key -> (value, expiry_monotonic | None)
        self._lock = asyncio.Lock()

    def _is_live(self, key: str) -> bool:
        entry = self._data.get(key)
        if entry is None:
            return False
        _, expiry = entry
        if expiry is not None and time.monotonic() >= expiry:
            del self._data[key]
            return False
        return True

    async def get(self, key: str) -> str | None:
        async with self._lock:
            if not self._is_live(key):
                return None
            return self._data[key][0]

    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        async with self._lock:
            expiry = time.monotonic() + ttl_seconds if ttl_seconds else None
            self._data[key] = (value, expiry)

    async def set_if_not_exists(self, key: str, value: str, ttl_seconds: int | None = None) -> bool:
        async with self._lock:
            if self._is_live(key):
                return False
            expiry = time.monotonic() + ttl_seconds if ttl_seconds else None
            self._data[key] = (value, expiry)
            return True

    async def incr(self, key: str, ttl_seconds: int | None = None) -> int:
        async with self._lock:
            if self._is_live(key):
                current = int(self._data[key][0])
                new_value = current + 1
                _, expiry = self._data[key]  # preserve original expiry -- fixed-window semantics
                self._data[key] = (str(new_value), expiry)
                return new_value
            expiry = time.monotonic() + ttl_seconds if ttl_seconds else None
            self._data[key] = ("1", expiry)
            return 1

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)
