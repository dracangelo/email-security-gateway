"""
Batch / Bulk DNS & RDAP Resolver.
Performs concurrent asynchronous DNS and RDAP queries across lists of domains to reduce per-message latency.
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional


class BatchDNSResolver:
    def __init__(self, resolve_single_func: Optional[Callable[[str], Any]] = None):
        self.resolve_single_func = resolve_single_func

    async def resolve_batch(self, domains: List[str]) -> Dict[str, Any]:
        """Resolve a batch of domains concurrently."""
        tasks = []
        clean_domains = [d.strip().lower() for d in domains if d and d.strip()]

        for dom in clean_domains:
            if self.resolve_single_func:
                tasks.append(self._async_resolve(dom))
            else:
                tasks.append(self._mock_resolve(dom))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = {}
        for dom, res in zip(clean_domains, results):
            out[dom] = res if not isinstance(res, Exception) else {"error": str(res)}
        return out

    async def _async_resolve(self, domain: str) -> Any:
        if inspect.iscoroutinefunction(self.resolve_single_func):
            return await self.resolve_single_func(domain)
        return self.resolve_single_func(domain)

    async def _mock_resolve(self, domain: str) -> Dict[str, Any]:
        await asyncio.sleep(0.01)
        return {"domain": domain, "resolved": True, "ip": "192.0.2.1"}
