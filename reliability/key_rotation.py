"""
Zero-Downtime Secret & Key Rotation Manager.
Supports dual-active key windows for Webhook secrets, Admin API keys, and Fernet encryption keys without dropping requests or locking out data during rotation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class SecretKeyVersion:
    key_value: str
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None  # None = current active primary


class ZeroDowntimeKeyRotator:
    """Manages secret rotation with overlapping validity windows for zero-downtime key rotation."""

    def __init__(self):
        self._secrets: dict[str, list[SecretKeyVersion]] = {}

    def set_primary_secret(self, secret_name: str, secret_val: str):
        if secret_name not in self._secrets:
            self._secrets[secret_name] = []
        self._secrets[secret_name].insert(0, SecretKeyVersion(key_value=secret_val))

    def rotate_secret(self, secret_name: str, new_secret_val: str, grace_period_seconds: float = 3600.0):
        if secret_name not in self._secrets or not self._secrets[secret_name]:
            self.set_primary_secret(secret_name, new_secret_val)
            return

        now = time.time()
        # Set grace expiry on previous primary secret
        current_primary = self._secrets[secret_name][0]
        current_primary.expires_at = now + grace_period_seconds

        # Insert new primary at index 0
        new_primary = SecretKeyVersion(key_value=new_secret_val)
        self._secrets[secret_name].insert(0, new_primary)

    def is_valid_secret(self, secret_name: str, check_value: str) -> bool:
        if secret_name not in self._secrets:
            return False

        now = time.time()
        valid_versions = []

        for ver in self._secrets[secret_name]:
            if ver.expires_at is None or ver.expires_at > now:
                valid_versions.append(ver)

        return any(ver.key_value == check_value for ver in valid_versions)

    def get_valid_secrets(self, secret_name: str) -> list[str]:
        if secret_name not in self._secrets:
            return []
        now = time.time()
        return [ver.key_value for ver in self._secrets[secret_name] if ver.expires_at is None or ver.expires_at > now]
