"""
Shared Process-Wide HTTP Connection Pool Manager.
Reuses httpx.AsyncClient connection pools across reputation, RDAP, and webhooks to eliminate TLS setup overhead.
"""
from __future__ import annotations

import httpx
from typing import Optional


class HTTPClientPool:
    """Singleton process-wide HTTP client pool manager."""

    _instance: Optional[HTTPClientPool] = None
    _client: Optional[httpx.AsyncClient] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_client(cls, timeout_sec: float = 10.0, timeout_seconds: float = 10.0) -> httpx.AsyncClient:
        inst = cls()
        tout = timeout_sec if timeout_sec != 10.0 else timeout_seconds
        if inst._client is None or inst._client.is_closed:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
            timeout = httpx.Timeout(tout)
            inst._client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
        return inst._client

    @classmethod
    async def close_client(cls):
        inst = cls()
        if inst._client is not None and not inst._client.is_closed:
            await inst._client.aclose()
            inst._client = None

    async def close(self):
        await self.close_client()


GlobalHTTPClientPool = HTTPClientPool
global_http_pool = HTTPClientPool()
