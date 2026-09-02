"""
Mailgun Inbound Routes payload parser.
"""
from __future__ import annotations

from .base import ParsedInboundMessage


def parse_mailgun_payload(form_data: dict) -> ParsedInboundMessage:
    envelope_from = str(form_data.get("sender", ""))
    recipient = str(form_data.get("recipient", ""))
    envelope_to = [recipient] if recipient else []

    from_header = str(form_data.get("from", ""))
    reply_to_header = str(form_data.get("reply-to", form_data.get("Reply-To", "")))
    text_body = str(form_data.get("body-plain", ""))
    html_body = str(form_data.get("body-html", ""))
    headers_blob = str(form_data.get("message-headers", ""))

    raw_mime = form_data.get("body-mime")
    has_raw = False
    if raw_mime and isinstance(raw_mime, (bytes, str)) and len(raw_mime) > 0:
        has_raw = True
        raw_bytes = raw_mime.encode("utf-8") if isinstance(raw_mime, str) else raw_mime
    else:
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
        provider_metadata={"provider": "mailgun"},
    )
