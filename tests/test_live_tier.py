"""
Explicitly-tiered Live Integration Test Suite.
These tests run against live DNS resolvers, live public RDAP services,
and live local SMTP servers.
Gated behind `--run-live` / `RUN_LIVE_TESTS=1`.
"""
import asyncio
import pytest
from auth_checker.spf import check_spf
from auth_checker.dmarc import fetch_dmarc_policy
from content_analysis.reputation import DomainAgeProvider
from delivery.relay import SMTPRelay, RelayError


@pytest.mark.live
class TestLiveDNSIntegration:
    """Live tests against real public DNS resolvers."""

    def test_live_dmarc_google(self):
        # google.com has a strict p=reject or quarantine DMARC policy
        policy = fetch_dmarc_policy("google.com")
        assert policy.record_found is True
        assert policy.policy in ("reject", "quarantine")

    def test_live_spf_cloudflare(self):
        # cloudflare.com publishes valid SPF record
        result = check_spf("cloudflare.com", sender_ip="1.1.1.1")
        assert result.record_found is True
        assert result.raw_record is not None
        assert "v=spf1" in result.raw_record


@pytest.mark.live
class TestLiveRDAPIntegration:
    """Live tests querying public ICANN RDAP endpoints."""

    def test_live_rdap_lookup_google(self):
        provider = DomainAgeProvider(timeout_seconds=10.0)
        age_days = provider.get_domain_age_days("google.com")
        if age_days is not None:
            # Google domain was registered in 1997 -> > 5000 days old
            assert age_days > 3650
        else:
            pytest.skip("Public RDAP endpoint rate-limited or temporarily unreachable")


@pytest.mark.live
class TestLiveSMTPE2EPipeline:
    """Live end-to-end integration test against a live local SMTP socket server."""

    @pytest.mark.anyio
    async def test_live_smtp_relay_transaction(self):
        received_messages = []

        class DummySMTPServer(asyncio.Protocol):
            def connection_made(self, transport):
                self.transport = transport
                self.transport.write(b"220 live-test-relay ESMTP ready\r\n")

            def data_received(self, data):
                msg = data.decode("utf-8", errors="ignore")
                if "EHLO" in msg or "HELO" in msg:
                    self.transport.write(b"250-live-test-relay\r\n250 HELP\r\n")
                elif "MAIL FROM:" in msg or "RCPT TO:" in msg:
                    self.transport.write(b"250 OK\r\n")
                elif "DATA" in msg:
                    self.transport.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                elif "\r\n.\r\n" in msg or msg.endswith(".\r\n") or msg.endswith(".\n"):
                    received_messages.append(msg)
                    self.transport.write(b"250 2.0.0 OK: message queued\r\n")
                elif "QUIT" in msg:
                    self.transport.write(b"221 2.0.0 Bye\r\n")
                    self.transport.close()
                else:
                    self.transport.write(b"250 OK\r\n")

        loop = asyncio.get_running_loop()
        server = await loop.create_server(DummySMTPServer, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            relay = SMTPRelay(
                host="127.0.0.1",
                port=port,
                use_tls=False,
                start_tls=False,
                timeout=5.0,
            )

            raw_email = (
                b"From: sender@example.com\r\n"
                b"To: recipient@example.com\r\n"
                b"Subject: Live SMTP Pipeline Test\r\n"
                b"\r\n"
                b"This is a live test body delivered over local TCP socket.\r\n"
            )

            await relay.send(
                raw_message=raw_email,
                mail_from="sender@example.com",
                rcpt_to=["recipient@example.com"],
            )

            assert len(received_messages) >= 1
        finally:
            server.close()
            await server.wait_closed()
