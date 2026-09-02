"""
Cache Warm-Up Engine for Frequent Partner Domains.
Pre-populates domain age and reputation caches for frequent domains to eliminate cold-start lookup latency.
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional, Set


class CacheWarmupEngine:
    def __init__(self, fetch_domain_info_func: Optional[Callable[[str], Any]] = None):
        self.fetch_domain_info_func = fetch_domain_info_func
        self.frequent_domains: Set[str] = set()
        self.cache: Dict[str, Any] = {}

    def add_frequent_domain(self, domain: str) -> None:
        self.frequent_domains.add(domain.strip().lower())

    async def warm_cache(self) -> int:
        """Pre-fetch and populate cache for all registered frequent domains."""
        count = 0
        for dom in list(self.frequent_domains):
            if self.fetch_domain_info_func:
                if inspect.iscoroutinefunction(self.fetch_domain_info_func):
                    res = await self.fetch_domain_info_func(dom)
                else:
                    res = self.fetch_domain_info_func(dom)
                self.cache[dom] = res
            else:
                self.cache[dom] = {"domain": dom, "warmed": True, "age_days": 3650}
            count += 1
        return count

    def get_cached_info(self, domain: str) -> Optional[Dict[str, Any]]:
        return self.cache.get(domain.strip().lower())
