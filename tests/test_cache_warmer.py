"""
Unit tests for domain cache warmer.
"""
import pytest
from scalability.cache_warmer import CacheWarmer


class MockAgeProvider:
    async def get_domain_age_days(self, domain: str) -> int:
        return 500


class MockReputationProvider:
    async def check_url(self, url: str) -> tuple[str, str]:
        return "clean", "mock"


@pytest.mark.anyio
async def test_cache_warmer():
    warmer = CacheWarmer(frequent_domains=["google.com", "microsoft.com"])
    warmed = await warmer.warm_cache(age_provider=MockAgeProvider(), reputation_provider=MockReputationProvider())
    assert warmed == 4
