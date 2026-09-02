"""
Identity & User Data Models.
Defines User account representation, role designations, password hashing, and credentials.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import os
import time
from typing import Any, Dict, List, Optional


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """PBKDF2-HMAC-SHA256 password hash."""
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{key.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored salt:hash."""
    try:
        salt_hex, key_hex = password_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        computed_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(computed_key, expected_key)
    except Exception:
        return False


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    role: str = "analyst"  # "admin", "analyst", "read_only"
    tenant_id: Optional[str] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    is_active: bool = True
    scopes: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        del data["password_hash"]
        if data.get("mfa_secret"):
            del data["mfa_secret"]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any], password_hash: str = "") -> User:
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            password_hash=password_hash or data.get("password_hash", ""),
            role=data.get("role", "analyst"),
            tenant_id=data.get("tenant_id"),
            mfa_enabled=data.get("mfa_enabled", False),
            mfa_secret=data.get("mfa_secret"),
            is_active=data.get("is_active", True),
            scopes=data.get("scopes", []),
            created_at=data.get("created_at", time.time()),
        )
