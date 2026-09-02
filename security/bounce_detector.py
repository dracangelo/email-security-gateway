"""
Bounce and Non-Delivery Report (NDR) loop prevention.
Detects automated system notifications, DSNs, and bounce messages to prevent
infinite mail loops through the gateway.
"""
from __future__ import annotations

import re


def is_bounce_or_ndr(envelope_from: str, headers_blob: str = "") -> tuple[bool, str]:
    """
    Checks if an inbound message is a bounce/NDR or automated system response.
    Returns (is_bounce, reason).
    """
    env_from_clean = (envelope_from or "").strip().lower()

    # 1. Empty envelope sender <> or mailer-daemon
    if not env_from_clean or env_from_clean in {"<>", "<mailer-daemon>", "mailer-daemon@"} or env_from_clean.startswith("postmaster@") or env_from_clean.startswith("mailer-daemon@"):
        return True, f"empty or system envelope sender ({envelope_from})"

    if not headers_blob:
        return False, ""

    headers_lower = headers_blob.lower()

    # 2. Auto-Submitted header
    if "auto-submitted:" in headers_lower:
        match = re.search(r"auto-submitted:\s*([^\r\n]+)", headers_lower)
        if match:
            val = match.group(1).strip()
            if val != "no":
                return True, f"Auto-Submitted header present: {val}"

    # 3. DSN Content-Type (multipart/report; report-type=delivery-status)
    if "report-type=delivery-status" in headers_lower or "multipart/report" in headers_lower:
        return True, "delivery-status notification (multipart/report) header"

    # 4. Subject checks for common bounce prefixes
    if re.search(r"subject:\s*(undeliverable:|delivery status notification|mail delivery failed)", headers_lower):
        return True, "subject indicates non-delivery report / mail failure notification"

    return False, ""
