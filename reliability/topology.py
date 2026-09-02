"""
Multi-AZ / Multi-Region Deployment Topology Manager.
Tracks regional health status, active-active / active-passive cluster mode, and failover routing state.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RegionHealth:
    region_name: str
    is_healthy: bool = True
    latency_ms: float = 12.0
    active_connections: int = 0


class MultiRegionTopology:
    """Manages multi-region deployment routing, health checks, and failover status."""

    def __init__(
        self,
        primary_region: str = "us-east-1",
        secondary_regions: list[str] | None = None,
        mode: str = "active-passive",
    ):
        self.primary_region = primary_region
        self.secondary_regions = secondary_regions or ["us-west-2", "eu-central-1"]
        self.mode = mode.lower()
        self._current_active_region = primary_region
        self._region_health: dict[str, RegionHealth] = {
            r: RegionHealth(region_name=r) for r in [primary_region] + self.secondary_regions
        }

    def is_primary_healthy(self) -> bool:
        return self._region_health.get(self.primary_region, RegionHealth(self.primary_region)).is_healthy

    def set_region_health(self, region_name: str, is_healthy: bool, latency_ms: float = 10.0):
        if region_name in self._region_health:
            self._region_health[region_name].is_healthy = is_healthy
            self._region_health[region_name].latency_ms = latency_ms

    def get_active_region(self) -> str:
        if self.mode == "active-active":
            healthy_regions = [r for r, h in self._region_health.items() if h.is_healthy]
            return healthy_regions[0] if healthy_regions else self.primary_region

        if self.is_primary_healthy():
            return self.primary_region

        # Failover to first healthy secondary region
        for sec in self.secondary_regions:
            if self._region_health[sec].is_healthy:
                logger.warning("Primary region %s unhealthy; failing over to %s", self.primary_region, sec)
                return sec

        return self.primary_region

    def trigger_failover(self, target_region: str) -> bool:
        if target_region in self._region_health and self._region_health[target_region].is_healthy:
            self._current_active_region = target_region
            logger.info("Manual failover triggered to region %s", target_region)
            return True
        return False

    def get_topology_status(self) -> dict:
        return {
            "mode": self.mode,
            "primary_region": self.primary_region,
            "active_region": self.get_active_region(),
            "regions": {
                r: {"is_healthy": h.is_healthy, "latency_ms": h.latency_ms}
                for r, h in self._region_health.items()
            },
        }
