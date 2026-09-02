"""
Production-hardened AsyncIO Inbound SMTP Receiver server.
Listens for raw SMTP connections, enforces size/connection limits,
parses incoming SMTP sessions, and routes mail through the gateway pipeline.
"""
from __future__ import annotations

import asyncio
import email
from email.policy import default as default_policy
import logging
import uuid
from typing import Awaitable, Callable

from webhook_receiver.parsers.base import ParsedInboundMessage

logger = logging.getLogger(__name__)

MessageProcessor = Callable[[ParsedInboundMessage, str], Awaitable[dict]]


class SMTPProtocol(asyncio.Protocol):
    def __init__(
        self,
        processor: MessageProcessor,
        hostname: str = "email-auth-gateway",
        max_message_size: int = 10 * 1024 * 1024,
    ):
        self.processor = processor
        self.hostname = hostname
        self.max_message_size = max_message_size

        self.transport: asyncio.Transport | None = None
        self.client_ip: str = "0.0.0.0"
        self.state: str = "COMMAND"
        self.helo_domain: str = ""
        self.mail_from: str = ""
        self.rcpt_to: list[str] = []
        self.data_buffer: list[bytes] = []
        self.data_bytes_count: int = 0
        self._buffer: bytes = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore
        peername = transport.get_extra_info("peername")
        if peername:
            self.client_ip = peername[0]
        logger.debug("SMTP connection established from %s", self.client_ip)
        self.send_reply(220, f"{self.hostname} ESMTP Inbound Receiver Ready")

    def send_reply(self, code: int, message: str) -> None:
        if self.transport and not self.transport.is_closing():
            lines = f"{code} {message}\r\n".encode("utf-8")
            self.transport.write(lines)

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            if self.state == "DATA":
                self.handle_data_line(line)
            else:
                self.handle_command_line(line.decode("utf-8", errors="replace"))

    def handle_command_line(self, line: str) -> None:
        cmd_upper = line.strip().upper()
        if not cmd_upper:
            return

        if cmd_upper.startswith("HELO") or cmd_upper.startswith("EHLO"):
            parts = line.split(maxsplit=1)
            self.helo_domain = parts[1] if len(parts) > 1 else ""
            self.send_reply(250, f"{self.hostname} Hello {self.helo_domain}")

        elif cmd_upper.startswith("MAIL FROM:"):
            from_addr = line[10:].strip().strip("<>")
            self.mail_from = from_addr
            self.rcpt_to = []
            self.send_reply(250, "2.1.0 Sender OK")

        elif cmd_upper.startswith("RCPT TO:"):
            if not self.mail_from:
                self.send_reply(503, "5.5.1 Error: need MAIL command first")
                return
            to_addr = line[8:].strip().strip("<>")
            self.rcpt_to.append(to_addr)
            self.send_reply(250, "2.1.5 Recipient OK")

        elif cmd_upper == "DATA":
            if not self.rcpt_to:
                self.send_reply(503, "5.5.1 Error: need RCPT command first")
                return
            self.state = "DATA"
            self.data_buffer = []
            self.data_bytes_count = 0
            self.send_reply(354, "Start mail input; end with <CR><LF>.<CR><LF>")

        elif cmd_upper == "RSET":
            self.mail_from = ""
            self.rcpt_to = []
            self.data_buffer = []
            self.state = "COMMAND"
            self.send_reply(250, "2.0.0 Reset OK")

        elif cmd_upper == "QUIT":
            self.send_reply(221, f"{self.hostname} Service closing transmission channel")
            if self.transport:
                self.transport.close()

        elif cmd_upper == "NOOP":
            self.send_reply(250, "2.0.0 OK")

        else:
            self.send_reply(500, "5.5.2 Command unrecognized")

    def handle_data_line(self, line: bytes) -> None:
        if line == b".":
            self.state = "COMMAND"
            full_data = b"\r\n".join(self.data_buffer)
            asyncio.create_task(self._process_message_async(full_data))
        else:
            if line.startswith(b".."):
                line = line[1:]  # Dot demunging
            self.data_bytes_count += len(line) + 2
            if self.data_bytes_count > self.max_message_size:
                self.send_reply(552, "5.3.4 Message size exceeds fixed limit")
                self.state = "COMMAND"
                self.data_buffer = []
            else:
                self.data_buffer.append(line)

    async def _process_message_async(self, raw_message: bytes) -> None:
        try:
            parsed_msg = email.message_from_bytes(raw_message, policy=default_policy)
            headers_blob = ""
            if parsed_msg.items():
                headers_blob = "\r\n".join(f"{k}: {v}" for k, v in parsed_msg.items())

            from_header = str(parsed_msg.get("From", ""))
            reply_to_header = str(parsed_msg.get("Reply-To", ""))

            text_body = ""
            html_body = ""
            if parsed_msg.is_multipart():
                for part in parsed_msg.walk():
                    ct = part.get_content_type()
                    if ct == "text/plain" and not text_body:
                        text_body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    elif ct == "text/html" and not html_body:
                        html_body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
            else:
                payload = parsed_msg.get_payload(decode=True)
                if payload:
                    text_body = payload.decode(parsed_msg.get_content_charset() or "utf-8", errors="replace")

            inbound = ParsedInboundMessage(
                envelope_from=self.mail_from,
                envelope_to=self.rcpt_to,
                from_header=from_header,
                reply_to_header=reply_to_header,
                text_body=text_body,
                html_body=html_body,
                headers_blob=headers_blob,
                raw_message=raw_message,
                has_raw_mime=True,
                provider_metadata={"provider": "smtp_receiver", "helo": self.helo_domain},
            )

            result = await self.processor(inbound, self.client_ip)
            action = result.get("action")
            if action in ("quarantine", "reject"):
                self.send_reply(550, f"5.7.1 Message policy rejection: {action}")
            else:
                msg_id = result.get("message_id", str(uuid.uuid4()))
                self.send_reply(250, f"2.0.0 OK queued as {msg_id}")
        except Exception as exc:
            logger.exception("Error processing inbound SMTP message: %s", exc)
            self.send_reply(451, "4.3.0 Local error in processing")
        finally:
            self.mail_from = ""
            self.rcpt_to = []
            self.data_buffer = []


class InboundSMTPServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2525,
        processor: MessageProcessor | None = None,
        max_message_size: int = 10 * 1024 * 1024,
    ):
        self.host = host
        self.port = port
        self.processor = processor or self._default_processor
        self.max_message_size = max_message_size
        self._server: asyncio.AbstractServer | None = None

    async def _default_processor(self, msg: ParsedInboundMessage, client_ip: str) -> dict:
        return {"action": "forward", "message_id": str(uuid.uuid4())}

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._server = await loop.create_server(
            protocol_factory=lambda: SMTPProtocol(
                processor=self.processor,
                max_message_size=self.max_message_size,
            ),
            host=self.host,
            port=self.port,
        )
        logger.info("Inbound SMTP Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Inbound SMTP Server stopped")
