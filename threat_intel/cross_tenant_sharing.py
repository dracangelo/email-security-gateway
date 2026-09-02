"""
Cross-Tenant Opt-In Threat Intelligence Sharing Engine.
Allows opted-in tenants to anonymously share and benefit from confirmed gateway threat indicators.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional, Set


class CrossTenantIOCSharer:
    def __init__(self):
        self.opted_in_tenants: Set[str] = set()
        self.shared_iocs: Dict[str, Dict[str, Any]] = {}  # ioc_value -> metadata

    def opt_in_tenant(self, tenant_id: str) -> None:
        """Opt a tenant into cross-tenant threat sharing."""
        self.opted_in_tenants.add(tenant_id)

    def opt_out_tenant(self, tenant_id: str) -> None:
        """Opt a tenant out of cross-tenant threat sharing."""
        self.opted_in_tenants.discard(tenant_id)

    def is_opted_in(self, tenant_id: str) -> bool:
        return tenant_id in self.opted_in_tenants

    def share_confirmed_ioc(
        self,
        reporting_tenant_id: str,
        ioc_value: str,
        ioc_type: str,
        confidence_score: int = 90,
    ) -> bool:
        """Anonymously publish a confirmed malicious IOC to the shared pool if reporting tenant is opted in."""
        if not self.is_opted_in(reporting_tenant_id):
            return False

        clean_val = ioc_value.lower().strip()
        if not clean_val:
            return False

        # Store without any tenant-identifying origin details (privacy preserving)
        self.shared_iocs[clean_val] = {
            "value": clean_val,
            "type": ioc_type,
            "confidence": confidence_score,
            "first_shared_timestamp": time.time(),
            "source": "network_threat_intel",
        }
        return True

    def check_shared_ioc(self, requesting_tenant_id: Optional[str], ioc_value: str) -> Optional[Dict[str, Any]]:
        """Query the shared threat pool if requesting tenant is opted in or global check."""
        if requesting_tenant_id and not self.is_opted_in(requesting_tenant_id):
            return None

        clean_val = ioc_value.lower().strip()
        return self.shared_iocs.get(clean_val)
