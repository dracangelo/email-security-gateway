import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
import pytest

from content_analysis.caching import CachedDomainAgeProvider, CachedReputationProvider
from content_analysis.reputation import (
    DomainAgeProvider,
    RDAPDomainAgeProvider,
    URLReputationProvider,
    VirusTotalProvider,
)
from resilience.circuit_breaker import CircuitBreaker
from storage.memory import InMemoryStore


def _run(coro):
    return asyncio.run(coro)


class _CountingTransport(httpx.AsyncBaseTransport):
    """Fails every request with a connection error, counting attempts."""

    def __init__(self):
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        raise httpx.ConnectError("simulated network failure", request=request)


class _FlakyThenOKTransport(httpx.AsyncBaseTransport):
    def __init__(self, fail_times: int, ok_response: httpx.Response):
        self.fail_times = fail_times
        self.ok_response = ok_response
        self.calls = 0

    async def handle_async_request(self, request):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise httpx.ConnectError("simulated transient failure", request=request)
        self.ok_response.request = request
        return self.ok_response


class TestRDAPRetryAndCircuitBreaker:
    def test_retries_then_gives_up_gracefully(self):
        transport = _CountingTransport()
        client = httpx.AsyncClient(transport=transport)
        provider = RDAPDomainAgeProvider(client=client, max_attempts=3, backoff_base=0.01)

        # Use a domain unlikely to collide with the shared module-level
        # breaker's state from other tests -- circuit breaker state is
        # process-global by design (see resilience/circuit_breaker.py).
        result = _run(provider.get_domain_age_days("retry-test-domain-1.example"))
        assert result is None  # degraded gracefully, did not raise
        assert transport.calls == 3  # actually retried max_attempts times

    def test_succeeds_after_transient_failure(self):
        ok_resp = httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]})
        transport = _FlakyThenOKTransport(fail_times=1, ok_response=ok_resp)
        client = httpx.AsyncClient(transport=transport)
        provider = RDAPDomainAgeProvider(client=client, max_attempts=3, backoff_base=0.01)

        result = _run(provider.get_domain_age_days("retry-test-domain-2.example"))
        assert result is not None
        assert result > 1000  # registered in 2020, definitely > 1000 days old
        assert transport.calls == 2  # one failure, one success


class TestVirusTotalGracefulDegradation:
    def test_no_api_key_returns_unknown_without_network_call(self):
        provider = VirusTotalProvider(api_key="")
        verdict, source = _run(provider.check_url("https://example.com"))
        assert verdict == "unknown"
        assert "no API key" in source

    def test_connection_failure_degrades_to_unknown(self):
        transport = _CountingTransport()
        client = httpx.AsyncClient(transport=transport)
        provider = VirusTotalProvider(api_key="fake-key", client=client, max_attempts=2, backoff_base=0.01)
        verdict, source = _run(provider.check_url("https://retry-test-vt.example/path"))
        assert verdict == "unknown"
        assert transport.calls == 2


class FakeDomainAgeProvider(DomainAgeProvider):
    def __init__(self, ages: dict[str, int | None]):
        self.ages = ages
        self.calls = 0

    async def get_domain_age_days(self, domain: str) -> int | None:
        self.calls += 1
        return self.ages.get(domain)


class FakeReputationProvider(URLReputationProvider):
    def __init__(self, verdicts: dict[str, tuple[str, str]]):
        self.verdicts = verdicts
        self.calls = 0

    async def check_url(self, url: str) -> tuple[str, str]:
        self.calls += 1
        return self.verdicts.get(url, ("unknown", "fake"))


class TestDomainAgeCaching:
    def test_second_call_hits_cache_not_wrapped_provider(self):
        underlying = FakeDomainAgeProvider({"example.com": 5000})
        cached = CachedDomainAgeProvider(underlying, InMemoryStore(), ttl_seconds=60)

        async def scenario():
            a = await cached.get_domain_age_days("example.com")
            b = await cached.get_domain_age_days("example.com")
            return a, b

        a, b = _run(scenario())
        assert a == b == 5000
        assert underlying.calls == 1  # second call served from cache

    def test_different_domains_dont_share_cache_entries(self):
        underlying = FakeDomainAgeProvider({"a.com": 10, "b.com": 20})
        cached = CachedDomainAgeProvider(underlying, InMemoryStore(), ttl_seconds=60)

        async def scenario():
            a = await cached.get_domain_age_days("a.com")
            b = await cached.get_domain_age_days("b.com")
            return a, b

        assert _run(scenario()) == (10, 20)
        assert underlying.calls == 2

    def test_none_result_is_cached_too(self):
        underlying = FakeDomainAgeProvider({})  # always returns None
        cached = CachedDomainAgeProvider(underlying, InMemoryStore(), ttl_seconds=60)

        async def scenario():
            await cached.get_domain_age_days("unknown.example")
            await cached.get_domain_age_days("unknown.example")

        _run(scenario())
        assert underlying.calls == 1  # second call still hit cache, not the provider


class TestReputationCaching:
    def test_second_call_hits_cache(self):
        underlying = FakeReputationProvider({"https://bad.example": ("malicious", "fake_vendor")})
        cached = CachedReputationProvider(underlying, InMemoryStore(), ttl_seconds=60)

        async def scenario():
            a = await cached.check_url("https://bad.example")
            b = await cached.check_url("https://bad.example")
            return a, b

        (v1, s1), (v2, s2) = _run(scenario())
        assert v1 == v2 == "malicious"
        assert "cached" in s2
        assert underlying.calls == 1
