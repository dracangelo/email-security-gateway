"""
Notifies someone when a message gets quarantined. Pluggable so a real
deployment can point this at Slack/Teams/PagerDuty/whatever without
touching the pipeline -- defaults to just logging, which is honest about
what this gateway can do with zero configuration (it can't page anyone
without being told how).
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

from resilience.retry import RetryExhausted, with_retry

logger = logging.getLogger("email_gateway.notify")


class Notifier(ABC):
    @abstractmethod
    async def notify_quarantine(self, quarantine_id: str, envelope_from: str, total_score: int, reasons: list[str]) -> bool:
        """Returns True if the notification was (best-effort) delivered."""


class LogNotifier(Notifier):
    """Default: just logs at WARNING. Zero configuration, zero external dependency."""

    async def notify_quarantine(self, quarantine_id: str, envelope_from: str, total_score: int, reasons: list[str]) -> bool:
        logger.warning(
            "QUARANTINED id=%s from=%s score=%d reasons=%s",
            quarantine_id, envelope_from, total_score, "; ".join(reasons),
        )
        return True


class WebhookNotifier(Notifier):
    """
    Posts a JSON payload to an incoming-webhook-style URL (Slack, Teams,
    or your own alerting endpoint all accept simple JSON POSTs like this,
    though the exact field name -- 'text' for Slack -- varies by target;
    adjust `_build_payload` for your receiver if it's not Slack-compatible).
    """

    def __init__(self, webhook_url: str, client: httpx.AsyncClient | None = None, timeout: float = 5.0,
                 max_attempts: int = 2, backoff_base: float = 0.5):
        self.webhook_url = webhook_url
        self._client = client
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base

    def _build_payload(self, quarantine_id: str, envelope_from: str, total_score: int, reasons: list[str]) -> dict:
        reason_text = "; ".join(reasons) if reasons else "(no specific reasons recorded)"
        return {
            "text": (
                f":rotating_light: Email quarantined (id `{quarantine_id}`)\n"
                f"From: {envelope_from}  Score: {total_score}\n"
                f"Reasons: {reason_text}"
            )
        }

    async def notify_quarantine(self, quarantine_id: str, envelope_from: str, total_score: int, reasons: list[str]) -> bool:
        if not self.webhook_url:
            return False
        payload = self._build_payload(quarantine_id, envelope_from, total_score, reasons)

        @with_retry(max_attempts=self._max_attempts, base_delay=self._backoff_base, retry_on=(httpx.RequestError,))
        async def _post() -> httpx.Response:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            owns_client = self._client is None
            try:
                return await client.post(self.webhook_url, json=payload)
            finally:
                if owns_client:
                    await client.aclose()

        try:
            resp = await _post()
        except RetryExhausted:
            logger.error("failed to deliver quarantine notification for %s after retries", quarantine_id)
            return False
        return resp.status_code < 300
