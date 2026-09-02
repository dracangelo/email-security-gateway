"""
Time-of-Click URL inspection and verification service.
Validates HMAC signatures and re-checks live URL reputation at click time.
"""
from __future__ import annotations

import base64
import logging
from typing import Tuple

from .rewriter import generate_url_signature

logger = logging.getLogger("email_gateway.time_of_click")


class TimeOfClickService:
    def __init__(self, secret_key: str, reputation_provider=None):
        self.secret_key = secret_key
        self.reputation_provider = reputation_provider

    def decode_and_verify(self, encoded_url: str, signature: str) -> Tuple[bool, str]:
        """Decodes target URL and verifies HMAC signature to prevent open redirect vulnerabilities."""
        if not encoded_url or not signature:
            return False, ""

        try:
            target_url = base64.urlsafe_b64decode(encoded_url.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            logger.warning("Failed to decode ToC URL: %s", exc)
            return False, ""

        expected_sig = generate_url_signature(target_url, self.secret_key)
        if not signature or signature != expected_sig:
            logger.warning("ToC signature mismatch for URL %s", target_url)
            return False, target_url

        return True, target_url

    async def evaluate_click(self, target_url: str) -> Tuple[bool, str]:
        """
        Re-checks live reputation at click-time.
        Returns (is_safe: bool, reason: str).
        """
        if not target_url:
            return False, "Empty or invalid URL"

        if self.reputation_provider is None:
            return True, "No live reputation provider configured; click allowed"

        try:
            verdict = await self.reputation_provider.check_url(target_url)
            if verdict.is_malicious:
                return False, f"URL flagged as malicious at click-time: {verdict.threat_type}"
            return True, "URL verified clean at click-time"
        except Exception as exc:
            logger.error("Click-time URL check error for %s: %s", target_url, exc)
            # Default fail-closed or fail-open per policy (here allow with log warning)
            return True, f"Click-time check degraded ({exc}); allowing redirect"
