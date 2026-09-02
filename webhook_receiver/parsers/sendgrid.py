"""
SendGrid Inbound Parse payload parser.
"""
from __future__ import annotations

import json
from .base import ParsedInboundMessage


def parse_sendgrid_payload(form_data: dict, raw_body_bytes: bytes | None = None) -> ParsedInboundMessage:
    envelope_raw = form_data.get("envelope", "{}")
    try:
        envelope = json.loads(envelope_raw) if isinstance(envelope_raw, str) else envelope_raw
    except (json.JSONDecodeError, TypeError):
        envelope = {}

    envelope_from = str(envelope.get("from", "")) if isinstance(envelope, dict) else ""
    envelope_to = envelope.get("to", []) if isinstance(envelope, dict) else []
    if isinstance(envelope_to, str):
        envelope_to = [envelope_to]

    from_header = str(form_data.get("from", ""))
    reply_to_header = str(form_data.get("reply-to", ""))
    headers_blob = str(form_data.get("headers", ""))
    text_body = str(form_data.get("text", ""))
    html_body = str(form_data.get("html", ""))

    # Raw MIME passthrough check
    raw_mime = form_data.get("email") or form_data.get("raw")
    has_raw = False
    if raw_mime and isinstance(raw_mime, (bytes, str)) and len(raw_mime) > 0:
        has_raw = True
        raw_bytes = raw_mime.encode("utf-8") if isinstance(raw_mime, str) else raw_mime
    else:
        # Fallback reconstructed raw bytes
        raw_bytes = (headers_blob + "\r\n\r\n" + text_body).encode("utf-8", errors="replace")

    return ParsedInboundMessage(
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        from_header=from_header,
        reply_to_header=reply_to_header,
        text_body=text_body,
        html_body=html_body,
        headers_blob=headers_blob,
        raw_message=raw_bytes,
        has_raw_mime=has_raw,
        provider_metadata={"provider": "sendgrid"},
    )
