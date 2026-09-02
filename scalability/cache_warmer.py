"""
Cache Warm-Up for Known-Frequent Partner & Vendor Domains.
Pre-populates reputation and RDAP domain-age caches to eliminate cold-start latency on frequent sender domains.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

DEFAULT_FREQUENT_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "apple.com",
    "amazon.com",
    "docusign.com",
    "salesforce.com",
]


class CacheWarmer:
    """Pre-warms reputation and domain age caches for frequent domains."""

    def __init__(self, frequent_domains: list[str] | None = None):
        self.frequent_domains = list(frequent_domains) if frequent_domains is not None else []
        self._cached_store: dict[str, dict] = {}

    def add_frequent_domain(self, domain: str):
        if domain not in self.frequent_domains:
            self.frequent_domains.append(domain)

    async def warm_cache(self, age_provider=None, reputation_provider=None) -> int:
        warmed_ops = 0
        domains_to_warm = self.frequent_domains or DEFAULT_FREQUENT_DOMAINS

        for domain in domains_to_warm:
            self._cached_store[domain] = {"warmed": True, "domain": domain}
            if age_provider is None and reputation_provider is None:
                warmed_ops += 1

            try:
                if age_provider is not None and hasattr(age_provider, "get_domain_age_days"):
                    await age_provider.get_domain_age_days(domain)
                    warmed_ops += 1
                if reputation_provider is not None and hasattr(reputation_provider, "check_url"):
                    await reputation_provider.check_url(f"https://{domain}")
                    warmed_ops += 1
            except Exception as exc:
                logger.debug("Failed cache warm-up for %s: %s", domain, exc)

        return warmed_ops

    def get_cached_info(self, domain: str) -> dict | None:
        return self._cached_store.get(domain)


CacheWarmupEngine = CacheWarmer
