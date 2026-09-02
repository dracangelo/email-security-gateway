"""
Secrets manager integration module supporting Vault, AWS Secrets Manager,
GCP Secret Manager, and environment variable fallbacks with TTL caching.
"""
from __future__ import annotations

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SecretsManagerError(Exception):
    """Base exception for secrets management errors."""
    pass


class SecretNotFoundError(SecretsManagerError):
    """Raised when a requested secret key is not found in the secret store."""
    pass


class BaseSecretsProvider(ABC):
    """Abstract base class for all secret providers."""

    @abstractmethod
    def get_secret(self, secret_name: str, key: Optional[str] = None) -> str:
        """
        Retrieve a secret value by name. If key is provided, extracts that specific key
        from a JSON-stored secret object.
        """
        pass


class EnvSecretsProvider(BaseSecretsProvider):
    """Provider that retrieves secrets from environment variables or local environment."""

    def __init__(self, env_prefix: str = ""):
        self.env_prefix = env_prefix

    def get_secret(self, secret_name: str, key: Optional[str] = None) -> str:
        env_var_name = f"{self.env_prefix}{secret_name}".upper().replace("-", "_").replace("/", "_")
        val = os.environ.get(env_var_name) or os.environ.get(secret_name)
        if val is None:
            raise SecretNotFoundError(f"Secret '{secret_name}' (env var '{env_var_name}') not found in environment.")

        if key:
            try:
                data = json.loads(val)
                if isinstance(data, dict) and key in data:
                    return str(data[key])
            except Exception:
                pass
            raise SecretNotFoundError(f"Key '{key}' not found in JSON secret payload for '{secret_name}'.")

        return val


class VaultSecretsProvider(BaseSecretsProvider):
    """Provider for HashiCorp Vault KV v2 secret engine."""

    def __init__(
        self,
        vault_url: str = "http://127.0.0.1:8200",
        token: str = "root",
        mount_point: str = "secret",
        http_client: Optional[Any] = None,
    ):
        self.vault_url = vault_url.rstrip("/")
        self.token = token
        self.mount_point = mount_point
        self._http_client = http_client
        self._mock_store: Dict[str, Dict[str, Any]] = {}

    def set_mock_secret(self, path: str, data: Dict[str, Any]) -> None:
        """Helper for testing or local simulation."""
        self._mock_store[path] = data

    def get_secret(self, secret_name: str, key: Optional[str] = None) -> str:
        if secret_name in self._mock_store:
            data = self._mock_store[secret_name]
            if key:
                if key not in data:
                    raise SecretNotFoundError(f"Key '{key}' not in Vault path '{secret_name}'.")
                return str(data[key])
            return json.dumps(data)

        if self._http_client:
            url = f"{self.vault_url}/v1/{self.mount_point}/data/{secret_name}"
            headers = {"X-Vault-Token": self.token}
            try:
                resp = self._http_client.get(url, headers=headers)
                if resp.status_code == 200:
                    body = resp.json()
                    secret_data = body.get("data", {}).get("data", {})
                    if key:
                        if key in secret_data:
                            return str(secret_data[key])
                        raise SecretNotFoundError(f"Key '{key}' not found in Vault path '{secret_name}'.")
                    return json.dumps(secret_data)
                elif resp.status_code == 404:
                    raise SecretNotFoundError(f"Vault path '{secret_name}' not found.")
            except Exception as e:
                if isinstance(e, SecretNotFoundError):
                    raise
                raise SecretsManagerError(f"Vault secret lookup failed: {e}") from e

        raise SecretNotFoundError(f"Vault secret '{secret_name}' unavailable.")


class AWSSecretsProvider(BaseSecretsProvider):
    """Provider for AWS Secrets Manager."""

    def __init__(self, region_name: str = "us-east-1", boto_client: Optional[Any] = None):
        self.region_name = region_name
        self._boto_client = boto_client
        self._mock_store: Dict[str, str] = {}

    def set_mock_secret(self, secret_name: str, secret_value: str) -> None:
        self._mock_store[secret_name] = secret_value

    def get_secret(self, secret_name: str, key: Optional[str] = None) -> str:
        if secret_name in self._mock_store:
            val = self._mock_store[secret_name]
            if key:
                data = json.loads(val)
                if key in data:
                    return str(data[key])
                raise SecretNotFoundError(f"Key '{key}' not in AWS secret '{secret_name}'.")
            return val

        if self._boto_client:
            try:
                res = self._boto_client.get_secret_value(SecretId=secret_name)
                val = res.get("SecretString", "")
                if key:
                    data = json.loads(val)
                    if key in data:
                        return str(data[key])
                    raise SecretNotFoundError(f"Key '{key}' not in AWS secret '{secret_name}'.")
                return val
            except Exception as e:
                raise SecretsManagerError(f"AWS Secrets Manager lookup failed: {e}") from e

        raise SecretNotFoundError(f"AWS secret '{secret_name}' unavailable.")


class GCPSecretsProvider(BaseSecretsProvider):
    """Provider for GCP Secret Manager."""

    def __init__(self, project_id: str = "default-project", gcp_client: Optional[Any] = None):
        self.project_id = project_id
        self._gcp_client = gcp_client
        self._mock_store: Dict[str, str] = {}

    def set_mock_secret(self, secret_id: str, payload: str) -> None:
        self._mock_store[secret_id] = payload

    def get_secret(self, secret_name: str, key: Optional[str] = None) -> str:
        if secret_name in self._mock_store:
            val = self._mock_store[secret_name]
            if key:
                data = json.loads(val)
                if key in data:
                    return str(data[key])
                raise SecretNotFoundError(f"Key '{key}' not in GCP secret '{secret_name}'.")
            return val

        if self._gcp_client:
            try:
                name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
                res = self._gcp_client.access_secret_version(request={"name": name})
                val = res.payload.data.decode("utf-8")
                if key:
                    data = json.loads(val)
                    if key in data:
                        return str(data[key])
                    raise SecretNotFoundError(f"Key '{key}' not in GCP secret '{secret_name}'.")
                return val
            except Exception as e:
                raise SecretsManagerError(f"GCP Secret Manager lookup failed: {e}") from e

        raise SecretNotFoundError(f"GCP secret '{secret_name}' unavailable.")


class SecretsManager:
    """
    Facade and caching secrets manager supporting chain of providers
    with TTL caching and fallback strategy.
    """

    def __init__(self, providers: Optional[list[BaseSecretsProvider]] = None, cache_ttl_seconds: int = 300):
        self.providers = providers or [EnvSecretsProvider()]
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, tuple[str, float]] = {}

    def get_secret(self, secret_name: str, key: Optional[str] = None, use_cache: bool = True) -> str:
        cache_key = f"{secret_name}:{key or ''}"
        now = time.monotonic()

        if use_cache and cache_key in self._cache:
            val, expiry = self._cache[cache_key]
            if now < expiry:
                return val

        last_error = None
        for provider in self.providers:
            try:
                val = provider.get_secret(secret_name, key=key)
                if use_cache and self.cache_ttl_seconds > 0:
                    self._cache[cache_key] = (val, now + self.cache_ttl_seconds)
                return val
            except (SecretNotFoundError, SecretsManagerError) as e:
                last_error = e
                continue

        raise SecretNotFoundError(
            f"Secret '{secret_name}' (key='{key}') could not be resolved by any secret provider."
        ) from last_error

    def clear_cache(self) -> None:
        self._cache.clear()


_global_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    global _global_secrets_manager
    if _global_secrets_manager is None:
        _global_secrets_manager = SecretsManager([EnvSecretsProvider()])
    return _global_secrets_manager


def set_secrets_manager(manager: SecretsManager) -> None:
    global _global_secrets_manager
    _global_secrets_manager = manager
