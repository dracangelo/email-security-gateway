"""
Geographic Data Residency Controls.
Enforces multi-tenant data jurisdiction rules ensuring tenant email data, quarantine items,
and encryption keys remain strictly within mandated geographic regions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


class DataResidencyViolationError(Exception):
    """Raised when an operation attempts to write tenant data outside approved geographic regions."""
    pass


@dataclass
class TenantResidencyPolicy:
    tenant_id: str
    primary_region: str
    allowed_regions: List[str] = field(default_factory=list)


class DataResidencyManager:
    """Manages tenant geographic data residency policies and validates storage operations."""

    def __init__(self, default_region: str = "us-east-1"):
        self.default_region = default_region
        self.policies: Dict[str, TenantResidencyPolicy] = {}

    def set_tenant_policy(self, tenant_id: str, primary_region: str, allowed_regions: Optional[List[str]] = None) -> TenantResidencyPolicy:
        regions = allowed_regions or [primary_region]
        if primary_region not in regions:
            regions.append(primary_region)

        policy = TenantResidencyPolicy(tenant_id=tenant_id, primary_region=primary_region, allowed_regions=regions)
        self.policies[tenant_id] = policy
        return policy

    def get_tenant_policy(self, tenant_id: str) -> TenantResidencyPolicy:
        if tenant_id in self.policies:
            return self.policies[tenant_id]
        return TenantResidencyPolicy(tenant_id=tenant_id, primary_region=self.default_region, allowed_regions=[self.default_region])

    def validate_storage_location(self, tenant_id: str, target_region: str) -> bool:
        """Check if target_region is compliant with tenant residency policy."""
        policy = self.get_tenant_policy(tenant_id)
        return target_region in policy.allowed_regions

    def enforce_residency(self, tenant_id: str, target_region: str) -> None:
        """Raises DataResidencyViolationError if target_region violates tenant residency rules."""
        if not self.validate_storage_location(tenant_id, target_region):
            policy = self.get_tenant_policy(tenant_id)
            raise DataResidencyViolationError(
                f"Data residency violation for tenant '{tenant_id}': region '{target_region}' "
                f"is not in allowed regions {policy.allowed_regions}."
            )
