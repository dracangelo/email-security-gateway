import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from security.rate_limit import RateLimitExceeded, RateLimiter
from security.redact import redact, redact_dict
from security.webhook_auth import WebhookAuthError, verify_secret, verify_source_ip
from storage.memory import InMemoryStore


def _run(coro):
    return asyncio.run(coro)


class TestWebhookSecret:
    def test_correct_secret_passes(self):
        verify_secret("correct-horse-battery-staple", "correct-horse-battery-staple")  # no raise

    def test_wrong_secret_raises_404(self):
        with pytest.raises(WebhookAuthError) as exc_info:
            verify_secret("wrong", "correct-horse-battery-staple")
        assert exc_info.value.status_code == 404  # not 401/403 -- don't confirm the endpoint exists

    def test_empty_expected_secret_is_noop(self):
        # Unauthenticated mode -- the caller logs the warning separately.
        verify_secret("anything", "")  # no raise

    def test_prefix_match_is_not_a_pass(self):
        with pytest.raises(WebhookAuthError):
            verify_secret("correct-horse-battery", "correct-horse-battery-staple")


class TestSourceIPAllowlist:
    def test_ip_in_range_passes(self):
        verify_source_ip("203.0.113.55", ["203.0.113.0/24"])  # no raise

    def test_ip_outside_range_rejected(self):
        with pytest.raises(WebhookAuthError):
            verify_source_ip("198.51.100.1", ["203.0.113.0/24"])

    def test_empty_allowlist_disables_check(self):
        verify_source_ip("1.2.3.4", [])  # no raise -- disabled

    def test_missing_client_ip_rejected_when_allowlist_active(self):
        with pytest.raises(WebhookAuthError):
            verify_source_ip(None, ["203.0.113.0/24"])

    def test_malformed_allowlist_entry_skipped_not_fatal(self):
        # "not-a-cidr" is garbage config -- should be skipped, not crash,
        # and the real entry should still work.
        verify_source_ip("203.0.113.5", ["not-a-cidr", "203.0.113.0/24"])


class TestRateLimiter:
    def test_allows_under_limit(self):
        limiter = RateLimiter(InMemoryStore(), max_requests=3, window_seconds=60)

        async def scenario():
            for _ in range(3):
                await limiter.check("1.2.3.4")  # should not raise

        _run(scenario())

    def test_blocks_over_limit(self):
        limiter = RateLimiter(InMemoryStore(), max_requests=2, window_seconds=60)

        async def scenario():
            await limiter.check("1.2.3.4")
            await limiter.check("1.2.3.4")
            await limiter.check("1.2.3.4")  # third call, over the limit of 2

        with pytest.raises(RateLimitExceeded):
            _run(scenario())

    def test_separate_identifiers_have_separate_limits(self):
        limiter = RateLimiter(InMemoryStore(), max_requests=1, window_seconds=60)

        async def scenario():
            await limiter.check("1.2.3.4")
            await limiter.check("5.6.7.8")  # different IP, should not be blocked by the first

        _run(scenario())  # no raise


class TestRedact:
    def test_redacts_key_value_pattern(self):
        assert "[REDACTED]" in redact("api_key: sk-abc123xyz")
        assert "sk-abc123xyz" not in redact("api_key: sk-abc123xyz")

    def test_redacts_bearer_token(self):
        out = redact("Authorization: Bearer abc.def-ghi_123")
        assert "abc.def-ghi_123" not in out

    def test_redacts_private_key_block(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG\n-----END PRIVATE KEY-----"
        out = redact(pem)
        assert "MIIBVQIBADANBgkqhkiG" not in out

    def test_leaves_clean_text_alone(self):
        text = "Hey, lunch tomorrow at noon?"
        assert redact(text) == text

    def test_redact_dict_hides_sensitive_keys_entirely(self):
        d = {"vt_api_key": "sk-live-abc123", "action": "quarantine"}
        out = redact_dict(d)
        assert out["vt_api_key"] == "[REDACTED]"
        assert out["action"] == "quarantine"

    def test_redact_dict_recurses_into_nested_dicts(self):
        d = {"config": {"webhook_shared_secret": "topsecret123"}}
        out = redact_dict(d)
        assert out["config"]["webhook_shared_secret"] == "[REDACTED]"

    def test_redact_dict_scans_string_values_for_leaked_secrets(self):
        d = {"body": "please send the api_key: sk-abc123xyz to finance"}
        out = redact_dict(d)
        assert "sk-abc123xyz" not in out["body"]
