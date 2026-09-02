"""
Bulk Newly Registered Domain (NRD) Watchlist Engine.
Maintains bulk daily NRD datasets for fast zero-latency age checking without per-message RDAP rate limits.
"""
from __future__ import annotations

import time
from typing import Dict, Optional, Set


class NRDWatchlistEngine:
    def __init__(self, max_age_days: int = 7):
        self.max_age_days = max_age_days
        self.nrd_store: Dict[str, float] = {}  # domain -> registration_timestamp

    def ingest_nrd_feed(self, domain_list_content: str, default_timestamp: Optional[float] = None) -> int:
        """Bulk ingest newly registered domain list. Returns count of added domains."""
        ts = default_timestamp or time.time()
        count = 0

        for line in domain_list_content.splitlines():
            domain = line.strip().lower()
            if not domain or domain.startswith("#"):
                continue

            self.nrd_store[domain] = ts
            count += 1

        return count

    def add_nrd(self, domain: str, registration_timestamp: Optional[float] = None) -> None:
        dom_clean = domain.strip().lower()
        if dom_clean:
            self.nrd_store[dom_clean] = registration_timestamp or time.time()

    def is_newly_registered(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if domain exists in NRD watchlist and return age info."""
        dom_clean = domain.strip().lower()
        reg_ts = self.nrd_store.get(dom_clean)
        if reg_ts is None:
            return None

        age_seconds = max(0.0, time.time() - reg_ts)
        age_days = round(age_seconds / 86400.0, 1)

        if age_days <= self.max_age_days:
            return {
                "domain": dom_clean,
                "is_nrd": True,
                "age_days": age_days,
                "registered_timestamp": reg_ts,
            }
        return None
