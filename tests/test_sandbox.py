"""
Unit tests for detonation sandbox integration.
"""
import pytest
from attachment_analysis.sandbox import DetonationSandboxClient


@pytest.mark.anyio
async def test_sandbox_null():
    client = DetonationSandboxClient(provider="null")
    res = await client.submit_sample("malware.exe", b"MZ data")
    assert res.is_submitted is False


@pytest.mark.anyio
async def test_sandbox_provider():
    client = DetonationSandboxClient(provider="cuckoo", api_url="http://sandbox.local")
    res = await client.submit_sample("suspicious.exe", b"MZ executable payload")
    assert res.is_submitted is True
    assert "cuckoo" in res.explanation
