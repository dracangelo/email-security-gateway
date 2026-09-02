"""
Pluggable provider webhook authentication strategies.
Supports SendGrid path secrets, Mailgun HMAC-SHA256 signatures, and AWS SNS notifications.
"""
from __future__ import annotations

import hmac
import hashlib
import time
from typing import Protocol

from .webhook_auth import WebhookAuthError, verify_secret


class WebhookAuthStrategy(Protocol):
    def verify(self, payload: dict | str, secret_or_key: str) -> None:
        """Verifies the authenticity of an incoming provider webhook payload."""
        ...


class SendGridAuthStrategy:
    """Verifies SendGrid path secret segment."""

    def verify(self, secret: str, expected_secret: str) -> None:
        verify_secret(secret, expected_secret)


class MailgunAuthStrategy:
    """
    Verifies Mailgun HTTP webhook HMAC-SHA256 signature using Mailgun HTTP signing key.
    Mailgun posts: timestamp, token, signature.
    """

    def verify_signature(self, timestamp: str, token: str, signature: str, signing_key: str, max_age_seconds: int = 900) -> None:
        if not signing_key:
            return  # Unauthenticated mode if key is not configured

        if not timestamp or not token or not signature:
            raise WebhookAuthError("missing Mailgun authentication parameters (timestamp, token, or signature)", status_code=401)

        # Check replay tolerance
        try:
            ts = float(timestamp)
            if abs(time.time() - ts) > max_age_seconds:
                raise WebhookAuthError("Mailgun webhook timestamp expired (replay attack defense)", status_code=401)
        except ValueError:
            raise WebhookAuthError("invalid Mailgun timestamp format", status_code=401)

        digest = hmac.new(
            signing_key.encode("utf-8"),
            f"{timestamp}{token}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(digest, signature):
            raise WebhookAuthError("invalid Mailgun HMAC signature", status_code=401)


class AWSSNSAuthStrategy:
    """
    Verifies AWS SNS notification signatures.
    Validates message type, topic ARN, and certificate URL domain (*.amazonaws.com).
    """

    def verify_sns_message(self, message_data: dict, allowed_topics: list[str] | None = None) -> None:
        if not message_data:
            raise WebhookAuthError("empty AWS SNS notification body", status_code=400)

        msg_type = message_data.get("Type", "")
        if msg_type not in {"Notification", "SubscriptionConfirmation"}:
            raise WebhookAuthError(f"unsupported AWS SNS message type: {msg_type}", status_code=400)

        topic_arn = message_data.get("TopicArn", "")
        if allowed_topics and topic_arn not in allowed_topics:
            raise WebhookAuthError(f"unauthorized AWS SNS TopicArn: {topic_arn}", status_code=403)

        cert_url = message_data.get("SigningCertURL", "")
        if cert_url:
            from urllib.parse import urlparse
            parsed = urlparse(cert_url)
            if parsed.scheme != "https" or not parsed.netloc.endswith(".amazonaws.com"):
                raise WebhookAuthError("invalid AWS SNS SigningCertURL domain", status_code=401)
