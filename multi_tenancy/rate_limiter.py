"""
Multi-Tenant Rate Limiting and Quota Enforcement.
Tracks request throughput per tenant dimension alongside IP-based rate limits.
"""
from __future__ import annotations

import logging
import time
from typing import Dict, Tuple

from security.rate_limit import RateLimitExceeded, RateLimiter

logger = logging.getLogger(__name__)


class TenantRateLimiter:
    def __init__(self, fallback_rate_limiter: RateLimiter | None = None):
        self.fallback_rate_limiter = fallback_rate_limiter
        # Storage: (tenant_id, minute_window) -> count
        self._tenant_counts: Dict[Tuple[str, int], int] = {}

    def check_tenant_rate_limit(self, tenant_id: str, max_requests_per_minute: int = 500) -> None:
        """Check if tenant has exceeded their allocated per-minute request quota."""
        now = time.time()
        minute_window = int(now // 60)
        key = (tenant_id, minute_window)

        # Cleanup old windows (> 2 mins ago)
        for k in list(self._tenant_counts.keys()):
            if k[1] < minute_window - 2:
                del self._tenant_counts[k]

        current_count = self._tenant_counts.get(key, 0)
        if current_count >= max_requests_per_minute:
            logger.warning("Tenant %s exceeded rate limit quota (%d/%d msgs/min)", tenant_id, current_count, max_requests_per_minute)
            raise RateLimitExceeded(tenant_id, max_requests_per_minute, 60)

        self._tenant_counts[key] = current_count + 1

    async def check_rate_limit(self, source_ip: str, tenant_id: str | None = None, max_tenant_rpm: int = 500) -> None:
        """Check both IP rate limit and tenant rate limit."""
        # 1. IP check
        if self.fallback_rate_limiter:
            await self.fallback_rate_limiter.check(source_ip)

        # 2. Tenant check if specified
        if tenant_id:
            self.check_tenant_rate_limit(tenant_id, max_requests_per_minute=max_tenant_rpm)
