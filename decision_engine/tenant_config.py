"""
Per-tenant scoring weights and routing thresholds configuration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from config import settings


@dataclass
class TenantConfig:
    tenant_id: str
    warn_threshold: int = settings.warn_threshold
    quarantine_threshold: int = settings.quarantine_threshold
    stage_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "auth": 1.0,
            "content": 1.0,
            "attachments": 1.0,
        }
    )
    vip_protection_enabled: bool = True
    shadow_mode_enabled: bool = False


class TenantConfigStore:
    def __init__(self):
        self._configs: Dict[str, TenantConfig] = {}

    def set_config(self, config: TenantConfig) -> None:
        self._configs[config.tenant_id] = config

    def get_config(self, tenant_id: str | None) -> TenantConfig:
        if not tenant_id or tenant_id not in self._configs:
            return TenantConfig(
                tenant_id=tenant_id or "default",
                warn_threshold=settings.warn_threshold,
                quarantine_threshold=settings.quarantine_threshold,
            )
        return self._configs[tenant_id]
