"""
Unit and integration tests for Inbound AsyncIO SMTP Receiver server.
"""
import asyncio
import pytest
from delivery.smtp_receiver import InboundSMTPServer
from webhook_receiver.parsers.base import ParsedInboundMessage


@pytest.mark.anyio
async def test_inbound_smtp_receiver_flow():
    received_messages = []

    async def mock_processor(msg: ParsedInboundMessage, client_ip: str) -> dict:
        received_messages.append((msg, client_ip))
        if "bad" in msg.from_header:
            return {"action": "quarantine", "message_id": "test-123"}
        return {"action": "forward", "message_id": "test-123"}

    server = InboundSMTPServer(host="127.0.0.1", port=25255, processor=mock_processor)
    await server.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 25255)

        # Read banner
        banner = await reader.readline()
        assert banner.startswith(b"220")

        # Send EHLO
        writer.write(b"EHLO test.client.com\r\n")
        await writer.drain()
        resp = await reader.readline()
        assert resp.startswith(b"250")

        # Send MAIL FROM
        writer.write(b"MAIL FROM:<alice@example.com>\r\n")
        await writer.drain()
        resp = await reader.readline()
        assert resp.startswith(b"250")

        # Send RCPT TO
        writer.write(b"RCPT TO:<bob@example.com>\r\n")
        await writer.drain()
        resp = await reader.readline()
        assert resp.startswith(b"250")

        # Send DATA
        writer.write(b"DATA\r\n")
        await writer.drain()
        resp = await reader.readline()
        assert resp.startswith(b"354")

        # Send body and finish
        raw_msg = (
            b"From: Alice <alice@example.com>\r\n"
            b"To: Bob <bob@example.com>\r\n"
            b"Subject: Test SMTP Inbound\r\n\r\n"
            b"Hello from SMTP test!\r\n.\r\n"
        )
        writer.write(raw_msg)
        await writer.drain()

        resp = await reader.readline()
        assert resp.startswith(b"250")

        # Send QUIT
        writer.write(b"QUIT\r\n")
        await writer.drain()
        resp = await reader.readline()
        assert resp.startswith(b"221")

        writer.close()
        await writer.wait_closed()

        assert len(received_messages) == 1
        msg, ip = received_messages[0]
        assert msg.envelope_from == "alice@example.com"
        assert msg.envelope_to == ["bob@example.com"]
        assert "Hello from SMTP test!" in msg.text_body

    finally:
        await server.stop()
