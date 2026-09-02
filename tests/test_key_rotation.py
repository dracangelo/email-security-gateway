"""
Unit tests for zero downtime key rotation manager.
"""
from reliability.key_rotation import ZeroDowntimeKeyRotator


def test_zero_downtime_key_rotator():
    rotator = ZeroDowntimeKeyRotator()
    rotator.set_primary_secret("webhook_secret", "secret_v1")

    assert rotator.is_valid_secret("webhook_secret", "secret_v1") is True
    assert rotator.is_valid_secret("webhook_secret", "secret_v2") is False

    # Rotate secret
    rotator.rotate_secret("webhook_secret", "secret_v2", grace_period_seconds=3600)

    # Both new primary and old secret remain valid during grace period
    assert rotator.is_valid_secret("webhook_secret", "secret_v2") is True
    assert rotator.is_valid_secret("webhook_secret", "secret_v1") is True

    valid_secrets = rotator.get_valid_secrets("webhook_secret")
    assert "secret_v2" in valid_secrets
    assert "secret_v1" in valid_secrets
