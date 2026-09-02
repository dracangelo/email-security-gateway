"""
Relays a message to its real destination mail server. This is the piece
that makes 'forward' and 'warn_and_strip' actually deliver something,
instead of the gateway being a pure decision API that nothing acts on.

Uses aiosmtplib (async, doesn't block the event loop) wrapped in
retry-with-backoff -- a destination mail server hiccuping mid-connection
shouldn't mean the message just silently never arrives.
"""
from __future__ import annotations

import aiosmtplib

from resilience.retry import RetryExhausted, with_retry


class RelayError(Exception):
    pass


class SMTPRelay:
    def __init__(
        self,
        host: str,
        port: int = 25,
        use_tls: bool = False,
        start_tls: bool = True,
        username: str = "",
        password: str = "",
        timeout: float = 15.0,
        max_attempts: int = 3,
        backoff_base: float = 0.5,
    ):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.start_tls = start_tls
        self.username = username
        self.password = password
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    async def send(self, raw_message: bytes, mail_from: str, rcpt_to: list[str]) -> None:
        """Raises RelayError if delivery fails after retries. Retries only
        on connection-level failures (SMTPConnectError, SMTPServerDisconnected,
        timeouts) -- never on a permanent SMTP rejection (5xx from the
        destination server), since retrying an address the destination just
        told us doesn't exist wastes time and looks like a retry-bomb to
        whoever's on the other end."""

        @with_retry(
            max_attempts=self._max_attempts,
            base_delay=self._backoff_base,
            retry_on=(aiosmtplib.SMTPConnectError, aiosmtplib.SMTPServerDisconnected, TimeoutError, ConnectionError),
        )
        async def _send() -> None:
            await aiosmtplib.send(
                raw_message,
                sender=mail_from,
                recipients=rcpt_to,
                hostname=self.host,
                port=self.port,
                use_tls=self.use_tls,
                start_tls=self.start_tls,
                username=self.username or None,
                password=self.password or None,
                timeout=self.timeout,
            )

        try:
            await _send()
        except RetryExhausted as exc:
            raise RelayError(f"failed to relay to {self.host}:{self.port} after retries: {exc.last_exception}") from exc
        except aiosmtplib.SMTPResponseException as exc:
            # Permanent rejection (bad recipient, policy reject, etc.) --
            # not retried, surfaces immediately as its own failure.
            raise RelayError(f"destination server rejected the message: {exc.code} {exc.message}") from exc
