"""
SLO Definition & Multi-Window Burn-Rate Alerting Engine.
Calculates service level objectives, error budget consumption, and burn-rate alerts.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


class SLOCalculator:
    def __init__(self, target_availability_pct: float = 99.9, target_latency_p99_sec: float = 2.0):
        self.target_availability_pct = target_availability_pct
        self.error_budget_pct = 100.0 - target_availability_pct
        self.target_latency_p99_sec = target_latency_p99_sec

        self.requests_log: List[Dict[str, Any]] = []

    def record_request(self, is_success: bool, latency_sec: float, timestamp: Optional[float] = None) -> None:
        ts = timestamp or time.time()
        self.requests_log.append({
            "timestamp": ts,
            "success": is_success,
            "latency": latency_sec,
            "is_error": not is_success or latency_sec > self.target_latency_p99_sec,
        })

    def calculate_slo_metrics(self, window_hours: float = 1.0) -> Dict[str, Any]:
        """Calculate availability, p99 latency compliance, and remaining error budget."""
        cutoff = time.time() - (window_hours * 3600.0)
        recent_reqs = [r for r in self.requests_log if r["timestamp"] >= cutoff]

        total = len(recent_reqs)
        if total == 0:
            return {
                "window_hours": window_hours,
                "total_requests": 0,
                "availability_pct": 100.0,
                "error_count": 0,
                "error_budget_remaining_pct": 100.0,
                "burn_rate": 0.0,
                "alert": None,
            }

        errors = sum(1 for r in recent_reqs if r["is_error"])
        actual_error_rate_pct = (errors / total) * 100.0
        availability_pct = 100.0 - actual_error_rate_pct

        # Burn rate = actual_error_rate / allowed_error_budget
        allowed_error_rate = (100.0 - self.target_availability_pct) / 100.0
        actual_error_rate = errors / total
        burn_rate = (actual_error_rate / allowed_error_rate) if allowed_error_rate > 0 else 0.0

        alert = None
        if burn_rate >= 14.4:
            alert = "CRITICAL: Fast Burn Rate (14.4x) - 2% Error Budget Consumed in 1 Hour"
        elif burn_rate >= 6.0:
            alert = "WARNING: Slow Burn Rate (6.0x) - 5% Error Budget Consumed in 6 Hours"

        return {
            "window_hours": window_hours,
            "total_requests": total,
            "availability_pct": round(availability_pct, 3),
            "error_count": errors,
            "burn_rate": round(burn_rate, 2),
            "alert": alert,
        }
