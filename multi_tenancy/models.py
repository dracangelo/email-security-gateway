"""
Multi-Tenancy Data Models.
Defines Tenant organization representation, settings, encryption keys, and quotas.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, List, Optional
from cryptography.fernet import Fernet


@dataclass
class Tenant:
    tenant_id: str
    name: str
    domains: List[str] = field(default_factory=list)
    status: str = "active"  # "active", "suspended", "offboarded"
    encryption_key: str = field(default_factory=lambda: Fernet.generate_key().decode("utf-8"))
    warn_threshold: int = 40
    quarantine_threshold: int = 70
    watchlist_domains: List[str] = field(default_factory=list)
    vt_api_key: Optional[str] = None
    gsb_api_key: Optional[str] = None
    relay_host: Optional[str] = None
    max_requests_per_minute: int = 500
    timezone: str = "UTC"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Tenant:
        return cls(
            tenant_id=data["tenant_id"],
            name=data.get("name", data["tenant_id"]),
            domains=data.get("domains", []),
            status=data.get("status", "active"),
            encryption_key=data.get("encryption_key") or Fernet.generate_key().decode("utf-8"),
            warn_threshold=data.get("warn_threshold", 40),
            quarantine_threshold=data.get("quarantine_threshold", 70),
            watchlist_domains=data.get("watchlist_domains", []),
            vt_api_key=data.get("vt_api_key"),
            gsb_api_key=data.get("gsb_api_key"),
            relay_host=data.get("relay_host"),
            max_requests_per_minute=data.get("max_requests_per_minute", 500),
            timezone=data.get("timezone", "UTC"),
            created_at=data.get("created_at", time.time()),
        )
