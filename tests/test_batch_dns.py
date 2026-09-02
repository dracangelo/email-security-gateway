"""
Unit tests for batch async DNS resolver.
"""
import pytest
from scalability.batch_dns import batch_resolve_domains, resolve_domain_single


@pytest.mark.anyio
async def test_resolve_domain_single():
    # Localhost resolution
    ip = await resolve_domain_single("localhost")
    assert ip in ("127.0.0.1", "::1", None)


@pytest.mark.anyio
async def test_batch_resolve_domains():
    res = await batch_resolve_domains(["localhost"], max_concurrency=2)
    assert "localhost" in res
