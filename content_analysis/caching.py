"""
Cache wrapper for any DomainAgeProvider / URLReputationProvider, backed by
the storage.KeyValueStore abstraction. Composable rather than baked into
each provider -- wrap once, works for RDAP, VirusTotal, Safe Browsing,
or anything else implementing the same small interface.

Domain age and URL reputation get different default TTLs on purpose:
domain registration age changes only in the sense of "gets older," so a
long cache is nearly always still correct hours later. A URL's reputation
verdict can flip (blocklists update, VT re-scans) much faster, so it's
cached more conservatively. Both are tunable per deployment via
config.settings.
"""
from __future__ import annotations

from .reputation import DomainAgeProvider, URLReputationProvider
from storage.base import KeyValueStore


class CachedDomainAgeProvider(DomainAgeProvider):
    def __init__(self, wrapped: DomainAgeProvider, store: KeyValueStore, ttl_seconds: int = 6 * 3600):
        self.wrapped = wrapped
        self.store = store
        self.ttl_seconds = ttl_seconds

    async def get_domain_age_days(self, domain: str) -> int | None:
        key = f"domain_age:{domain}"
        cached = await self.store.get(key)
        if cached is not None:
            return None if cached == "" else int(cached)

        result = await self.wrapped.get_domain_age_days(domain)
        # Cache a lookup FAILURE too (as an empty-string sentinel), but only
        # for a short window -- otherwise one transient RDAP hiccup gets
        # treated as "permanently unknown" for the full TTL, which for a
        # 6-hour domain-age cache would mean re-scoring every future email
        # from that domain as "age unknown" for the rest of the workday.
        if result is None:
            await self.store.set(key, "", ttl_seconds=min(300, self.ttl_seconds))
        else:
            await self.store.set(key, str(result), ttl_seconds=self.ttl_seconds)
        return result


class CachedReputationProvider(URLReputationProvider):
    def __init__(self, wrapped: URLReputationProvider, store: KeyValueStore, ttl_seconds: int = 1800):
        self.wrapped = wrapped
        self.store = store
        self.ttl_seconds = ttl_seconds

    async def check_url(self, url: str) -> tuple[str, str]:
        key = f"url_reputation:{url}"
        cached = await self.store.get(key)
        if cached is not None:
            verdict, _, source = cached.partition("\x00")
            return verdict, source + " (cached)"

        verdict, source = await self.wrapped.check_url(url)
        # Same reasoning as domain age: cache "unknown" results too, but
        # for a much shorter window, so a transient provider outage
        # doesn't get treated as a settled verdict for the full TTL.
        ttl = self.ttl_seconds if verdict != "unknown" else min(120, self.ttl_seconds)
        await self.store.set(key, f"{verdict}\x00{source}", ttl_seconds=ttl)
        return verdict, source
