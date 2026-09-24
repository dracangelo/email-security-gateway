"""
Tenant Management and Provisioning Engine.
Manages onboarding, configuration updates, domain-to-tenant mapping, and offboarding workflows.
"""
from __future__ import annotations

import logging
import os
import shutil
from typing import Dict, List, Optional

from multi_tenancy.models import Tenant

logger = logging.getLogger(__name__)


class TenantManager:
    def __init__(self):
        self._tenants: Dict[str, Tenant] = {}
        self._domain_map: Dict[str, str] = {}  # domain -> tenant_id

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        domains: Optional[List[str]] = None,
        encryption_key: Optional[str] = None,
        warn_threshold: int = 40,
        quarantine_threshold: int = 70,
        max_requests_per_minute: int = 500,
        vt_api_key: Optional[str] = None,
        gsb_api_key: Optional[str] = None,
        timezone: str = "UTC",
    ) -> Tenant:
        """Onboard a new tenant."""
        if tenant_id in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' already exists")

        domains_list = [d.lower() for d in (domains or [])]
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            domains=domains_list,
            warn_threshold=warn_threshold,
            quarantine_threshold=quarantine_threshold,
            max_requests_per_minute=max_requests_per_minute,
            vt_api_key=vt_api_key,
            gsb_api_key=gsb_api_key,
            timezone=timezone,
        )
        if encryption_key:
            tenant.encryption_key = encryption_key

        self._tenants[tenant_id] = tenant
        for d in domains_list:
            self._domain_map[d] = tenant_id

        logger.info("Provisioned tenant %s (%s) with %d domains", tenant_id, name, len(domains_list))
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        return self._tenants.get(tenant_id)

    def get_tenant_by_domain(self, domain: str) -> Optional[Tenant]:
        """Resolve tenant from recipient or sender domain."""
        domain_lower = domain.lower().strip()
        if "@" in domain_lower:
            domain_lower = domain_lower.split("@")[-1]

        tenant_id = self._domain_map.get(domain_lower)
        if tenant_id:
            return self._tenants.get(tenant_id)

        # Check wildcard/parent domain
        parts = domain_lower.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[1:])
            tenant_id = self._domain_map.get(parent)
            if tenant_id:
                return self._tenants.get(tenant_id)

        return None

    def update_tenant(self, tenant_id: str, **kwargs) -> Tenant:
        """Update existing tenant configuration."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant '{tenant_id}' not found")

        if "domains" in kwargs:
            new_domains = [d.lower() for d in kwargs.pop("domains")]
            # Clean old domain maps
            for d in list(tenant.domains):
                if self._domain_map.get(d) == tenant_id:
                    del self._domain_map[d]
            tenant.domains = new_domains
            for d in new_domains:
                self._domain_map[d] = tenant_id

        for key, value in kwargs.items():
            if hasattr(tenant, key) and value is not None:
                setattr(tenant, key, value)

        logger.info("Updated configuration for tenant %s", tenant_id)
        return tenant

    def deprovision_tenant(self, tenant_id: str, purge_data: bool = True, storage_base_dir: Optional[str] = None) -> bool:
        """Offboard tenant and optionally purge isolated data storage directory."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False

        tenant.status = "offboarded"
        # Remove domain mappings
        for d in tenant.domains:
            if self._domain_map.get(d) == tenant_id:
                del self._domain_map[d]

        del self._tenants[tenant_id]

        if purge_data and storage_base_dir:
            tenant_dir = os.path.join(storage_base_dir, tenant_id)
            if os.path.exists(tenant_dir):
                shutil.rmtree(tenant_dir, ignore_errors=True)
                logger.info("Purged tenant %s isolated data storage at %s", tenant_id, tenant_dir)

        logger.info("Deprovisioned tenant %s", tenant_id)
        return True

    def list_tenants(self) -> List[Tenant]:
        return list(self._tenants.values())
