import json
import os
import pytest
from unittest.mock import MagicMock

from security.secrets_manager import (
    AWSSecretsProvider,
    EnvSecretsProvider,
    GCPSecretsProvider,
    SecretNotFoundError,
    SecretsManager,
    SecretsManagerError,
    VaultSecretsProvider,
    get_secrets_manager,
    set_secrets_manager,
)


def test_env_secrets_provider(monkeypatch):
    monkeypatch.setenv("WEBHOOK_SHARED_SECRET", "super-secret-123")
    monkeypatch.setenv("JSON_SECRET", json.dumps({"api_key": "key-99", "tier": "gold"}))

    provider = EnvSecretsProvider()
    assert provider.get_secret("WEBHOOK_SHARED_SECRET") == "super-secret-123"
    assert provider.get_secret("JSON_SECRET", key="api_key") == "key-99"

    with pytest.raises(SecretNotFoundError):
        provider.get_secret("NON_EXISTENT_VAR")

    with pytest.raises(SecretNotFoundError):
        provider.get_secret("JSON_SECRET", key="missing_key")


def test_vault_secrets_provider():
    vault = VaultSecretsProvider()
    vault.set_mock_secret("app/config", {"db_pass": "vault-pass-123", "role": "admin"})

    assert vault.get_secret("app/config", key="db_pass") == "vault-pass-123"
    with pytest.raises(SecretNotFoundError):
        vault.get_secret("app/config", key="non_existent")

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"data": {"api_key": "vault-api-key"}}}
    mock_client.get.return_value = mock_resp

    vault_http = VaultSecretsProvider(http_client=mock_client)
    assert vault_http.get_secret("prod/api", key="api_key") == "vault-api-key"


def test_aws_gcp_secrets_providers():
    aws = AWSSecretsProvider()
    aws.set_mock_secret("prod/vt_key", json.dumps({"key": "aws-vt-123"}))
    assert aws.get_secret("prod/vt_key", key="key") == "aws-vt-123"

    gcp = GCPSecretsProvider()
    gcp.set_mock_secret("gsb_key", json.dumps({"key": "gcp-gsb-456"}))
    assert gcp.get_secret("gsb_key", key="key") == "gcp-gsb-456"


def test_secrets_manager_caching_and_fallback(monkeypatch):
    monkeypatch.setenv("GLOBAL_KEY", "fallback-val")

    vault = VaultSecretsProvider()
    env = EnvSecretsProvider()

    manager = SecretsManager(providers=[vault, env], cache_ttl_seconds=60)
    assert manager.get_secret("GLOBAL_KEY") == "fallback-val"

    vault.set_mock_secret("GLOBAL_KEY", {"data": "vault-primary"})
    # Cached answer is still fallback-val
    assert manager.get_secret("GLOBAL_KEY") == "fallback-val"

    manager.clear_cache()
    # Now it hits vault first
    val = manager.get_secret("GLOBAL_KEY")
    assert "vault-primary" in val


def test_global_secrets_manager_helper():
    mgr = get_secrets_manager()
    assert isinstance(mgr, SecretsManager)
    new_mgr = SecretsManager([])
    set_secrets_manager(new_mgr)
    assert get_secrets_manager() is new_mgr
