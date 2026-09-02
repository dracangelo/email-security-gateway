"""
Chaos and Fault-Injection Resilience Test Suite.
Verifies system behavior and graceful degradation under multiple cascading failure modes.
"""
import asyncio
from unittest.mock import patch, MagicMock
import pytest

from storage.memory import InMemoryStore
from delivery.relay import SMTPRelay, RelayError
from attachment_analysis.reputation import ClamAVScanner
from content_analysis.reputation import VirusTotalProvider
from webhook_receiver.parsers import parse_sendgrid_payload


@pytest.mark.chaos
class TestChaosResilience:
    """Fault injection tests for distributed infrastructure failures."""

    @pytest.mark.anyio
    async def test_memory_fallback_deduplication(self):
        """Fault: Redis is unavailable, fallback InMemoryStore handles deduplication and rate limiting."""
        store = InMemoryStore()

        # 1. Deduplication via set_if_not_exists
        is_first = await store.set_if_not_exists("dedup:msg-12345", "1", ttl_seconds=60)
        assert is_first is True

        is_dup = await store.set_if_not_exists("dedup:msg-12345", "1", ttl_seconds=60)
        assert is_dup is False  # Duplicate correctly recognized in fallback store

        # 2. Rate limiting counter via incr
        count = await store.incr("rate:192.0.2.1", ttl_seconds=60)
        assert count == 1
        count2 = await store.incr("rate:192.0.2.1", ttl_seconds=60)
        assert count2 == 2

    @pytest.mark.anyio
    async def test_smtp_relay_connection_refused_resilience(self):
        """Fault: Destination SMTP server is completely down / connection refused."""
        relay = SMTPRelay(host="127.0.0.1", port=59999, timeout=0.5, max_attempts=1)

        raw_email = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nTest"
        with pytest.raises(RelayError):
            await relay.send(
                raw_message=raw_email,
                mail_from="a@b.com",
                rcpt_to=["c@d.com"],
            )

    @pytest.mark.anyio
    async def test_clamav_daemon_hang_and_fail_open(self):
        """Fault: ClamAV daemon is unreachable / down. Must fail open safely."""
        scanner = ClamAVScanner(host="192.0.2.1", port=3310, timeout=0.2)

        # Scanner should fail open and return error: detail rather than raising uncaught exception
        res = await scanner.scan(b"sample clean payload")
        assert res.startswith("error:")

    @pytest.mark.anyio
    async def test_threat_intel_rate_limit_429_resilience(self):
        """Fault: VirusTotal / external API returns 429 Too Many Requests."""
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp

            provider = VirusTotalProvider(api_key="fake-key")
            verdict, detail = await provider.check_url("https://example-phish-domain.com/login")

            # Must degrade gracefully to unknown/safe score without crashing
            assert verdict == "unknown"
            assert "429" in detail

    def test_corrupted_mime_stream_recovery(self):
        """Fault: Truncated / malformed MIME stream with missing boundary."""
        malformed_form_data = {
            "from": "attacker@evil.com",
            "to": "victim@example.com",
            "subject": "Corrupted MIME Email",
            "email": "--incomplete-boundary\r\nContent-Type: text/plain\r\n\r\nHello truncated mail",
        }

        # Parser should extract whatever text is available and not crash
        parsed = parse_sendgrid_payload(malformed_form_data)
        assert parsed.from_header == "attacker@evil.com"
        assert parsed.has_raw_mime is True
        assert len(parsed.raw_message) > 0
