"""
Cryptographic and Data Storage Isolation for Multi-Tenant Environments.
Enforces per-tenant Fernet encryption key isolation and directory namespaces.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from delivery.quarantine import QuarantineRecord, QuarantineStore
from multi_tenancy.models import Tenant
from multi_tenancy.tenant_manager import TenantManager
from security.encryption import RawMailCipher

logger = logging.getLogger(__name__)


class TenantIsolatedCipher:
    def __init__(self):
        self._ciphers: Dict[str, RawMailCipher] = {}

    def get_cipher_for_tenant(self, tenant: Tenant) -> RawMailCipher:
        """Get or create dedicated RawMailCipher for tenant."""
        if tenant.tenant_id not in self._ciphers:
            cipher = RawMailCipher(key=tenant.encryption_key)
            self._ciphers[tenant.tenant_id] = cipher
        return self._ciphers[tenant.tenant_id]


class TenantIsolatedQuarantine:
    def __init__(self, base_quarantine_dir: str, tenant_manager: TenantManager):
        self.base_quarantine_dir = base_quarantine_dir
        self.tenant_manager = tenant_manager
        self.isolated_cipher = TenantIsolatedCipher()
        self._stores: Dict[str, QuarantineStore] = {}

    def get_store_for_tenant(self, tenant_id: str) -> QuarantineStore:
        """Get or initialize isolated QuarantineStore for a given tenant."""
        if tenant_id not in self._stores:
            tenant = self.tenant_manager.get_tenant(tenant_id)
            cipher = self.isolated_cipher.get_cipher_for_tenant(tenant) if tenant else None
            tenant_dir = os.path.join(self.base_quarantine_dir, tenant_id)
            os.makedirs(tenant_dir, exist_ok=True)

            store = QuarantineStore(quarantine_dir=tenant_dir, cipher=cipher)
            self._stores[tenant_id] = store

        return self._stores[tenant_id]

    async def store(
        self,
        tenant_id: str,
        raw_message: bytes,
        message_id: str,
        envelope_from: str,
        envelope_to: List[str],
        total_score: int,
        action: str,
        reasons: List[str],
    ) -> QuarantineRecord:
        """Store message under tenant's isolated directory namespace encrypted with tenant's key."""
        store = self.get_store_for_tenant(tenant_id)
        return await store.store(
            raw_message=raw_message,
            message_id=message_id,
            envelope_from=envelope_from,
            envelope_to=envelope_to,
            total_score=total_score,
            action=action,
            reasons=reasons,
        )

    def list_pending(self, tenant_id: str) -> List[QuarantineRecord]:
        store = self.get_store_for_tenant(tenant_id)
        return store.list_pending()
