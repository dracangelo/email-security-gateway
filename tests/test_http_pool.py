"""
Unit tests for shared process-wide HTTP connection pool.
"""
import pytest
from scalability.http_pool import HTTPClientPool


@pytest.mark.anyio
async def test_http_client_pool():
    pool = HTTPClientPool()
    client = pool.get_client()
    assert client is not None
    assert not client.is_closed

    client2 = pool.get_client()
    assert client is client2

    await pool.close()
    assert client.is_closed
