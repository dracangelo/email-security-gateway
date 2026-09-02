"""
External API Cost & Quota Tracker.
Tracks metered API usage across external providers (VirusTotal, AbuseIPDB) and triggers quota exhaustion alerts.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


class QuotaTracker:
    def __init__(self):
        # provider -> {"daily_limit": int, "daily_used": int, "monthly_limit": int, "monthly_used": int}
        self.quotas: Dict[str, Dict[str, int]] = {}

    def set_provider_quota(
        self,
        provider: str,
        daily_limit: int = 1000,
        monthly_limit: int = 30000,
    ) -> None:
        self.quotas[provider.lower()] = {
            "daily_limit": daily_limit,
            "daily_used": 0,
            "monthly_limit": monthly_limit,
            "monthly_used": 0,
        }

    def record_api_call(self, provider: str, count: int = 1) -> Dict[str, Any]:
        """Record usage and return current quota status + alert state."""
        p_clean = provider.lower()
        if p_clean not in self.quotas:
            self.set_provider_quota(p_clean)

        quota = self.quotas[p_clean]
        quota["daily_used"] += count
        quota["monthly_used"] += count

        daily_pct = (quota["daily_used"] / quota["daily_limit"] * 100.0) if quota["daily_limit"] > 0 else 0.0
        monthly_pct = (quota["monthly_used"] / quota["monthly_limit"] * 100.0) if quota["monthly_limit"] > 0 else 0.0

        alert = None
        if daily_pct >= 90.0 or monthly_pct >= 90.0:
            alert = f"CRITICAL: {provider} quota usage at {max(daily_pct, monthly_pct):.1f}% of limit"
        elif daily_pct >= 80.0 or monthly_pct >= 80.0:
            alert = f"WARNING: {provider} quota usage at {max(daily_pct, monthly_pct):.1f}% of limit"

        return {
            "provider": provider,
            "daily_used": quota["daily_used"],
            "daily_limit": quota["daily_limit"],
            "daily_pct": round(daily_pct, 1),
            "monthly_used": quota["monthly_used"],
            "monthly_limit": quota["monthly_limit"],
            "monthly_pct": round(monthly_pct, 1),
            "alert": alert,
        }

    def reset_daily_quotas(self) -> None:
        for q in self.quotas.values():
            q["daily_used"] = 0
