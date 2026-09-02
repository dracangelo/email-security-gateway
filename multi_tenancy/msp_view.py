"""
MSP / Reseller Cross-Tenant Dashboard View Engine.
Renders aggregate multi-tenant statistics, threat levels, and quarantine metrics
without leaking raw email contents or tenant PII.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from multi_tenancy.isolation import TenantIsolatedQuarantine
from multi_tenancy.tenant_manager import TenantManager

logger = logging.getLogger(__name__)


class MSPAdminView:
    def __init__(self, tenant_manager: TenantManager, isolated_quarantine: TenantIsolatedQuarantine):
        self.tenant_manager = tenant_manager
        self.isolated_quarantine = isolated_quarantine
        # Tracking: tenant_id -> count of processed msgs
        self._processed_counts: Dict[str, int] = {}

    def record_message_processed(self, tenant_id: str) -> None:
        self._processed_counts[tenant_id] = self._processed_counts.get(tenant_id, 0) + 1

    def generate_dashboard_summary(self) -> Dict[str, Any]:
        """Build cross-tenant MSP overview summary."""
        tenants = self.tenant_manager.list_tenants()
        total_tenants = len(tenants)
        active_tenants = sum(1 for t in tenants if t.status == "active")

        tenant_summaries = []
        total_quarantined_all = 0

        for t in tenants:
            pending = self.isolated_quarantine.list_pending(t.tenant_id)
            q_count = len(pending)
            total_quarantined_all += q_count

            tenant_summaries.append(
                {
                    "tenant_id": t.tenant_id,
                    "name": t.name,
                    "status": t.status,
                    "domains_count": len(t.domains),
                    "messages_processed": self._processed_counts.get(t.tenant_id, 0),
                    "pending_quarantine_count": q_count,
                    "created_at": t.created_at,
                }
            )

        return {
            "generated_at": time.time(),
            "aggregate_metrics": {
                "total_tenants": total_tenants,
                "active_tenants": active_tenants,
                "total_messages_processed": sum(self._processed_counts.values()),
                "total_pending_quarantine": total_quarantined_all,
            },
            "tenants": tenant_summaries,
        }
