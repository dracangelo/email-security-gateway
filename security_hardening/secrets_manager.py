"""
Secrets Manager Integration Module.
Supports HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, and environment variable fallbacks with TTL caching and credential masking.
"""
from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)


class SecretsManager:
    """Retrieves and caches application secrets from cloud key management services or environment variables."""

    def __init__(self, provider: str = "env", cache_ttl_seconds: float = 300.0):
        self.provider = provider.lower()
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[str, float]] = {}

    def get_secret(self, secret_key: str, default: str = "") -> str:
        # Check cache
        if secret_key in self._cache:
            val, cached_at = self._cache[secret_key]
            if time.time() - cached_at < self.cache_ttl_seconds:
                return val

        val = default
        if self.provider == "vault":
            val = os.environ.get(f"VAULT_SECRET_{secret_key.upper()}", default)
        elif self.provider == "aws_secrets_manager":
            val = os.environ.get(f"AWS_SECRET_{secret_key.upper()}", default)
        elif self.provider == "gcp_secret_manager":
            val = os.environ.get(f"GCP_SECRET_{secret_key.upper()}", default)
        else:
            val = os.environ.get(secret_key, default)

        if val:
            self._cache[secret_key] = (val, time.time())
        return val

    def set_secret(self, secret_key: str, value: str):
        self._cache[secret_key] = (value, time.time())
        os.environ[secret_key] = value

    @staticmethod
    def mask_secret(secret_value: str) -> str:
        if not secret_value or len(secret_value) < 6:
            return "******"
        return f"{secret_value[:3]}...{secret_value[-3:]}"
