"""
Postmark Inbound Email Webhook payload parser.
"""
from __future__ import annotations

from .base import ParsedInboundMessage


def parse_postmark_payload(json_data: dict) -> ParsedInboundMessage:
    """
    Parse a Postmark Inbound Webhook JSON payload into ParsedInboundMessage.
    """
    envelope_from = str(json_data.get("From", ""))
    
    # Extract envelope destination
    envelope_to: list[str] = []
    to_full = json_data.get("ToFull", [])
    if isinstance(to_full, list):
        for t in to_full:
            if isinstance(t, dict) and t.get("Email"):
                envelope_to.append(str(t["Email"]))
    if not envelope_to and json_data.get("To"):
        envelope_to = [str(json_data["To"])]
    if not envelope_to and json_data.get("OriginalRecipient"):
        envelope_to = [str(json_data["OriginalRecipient"])]

    from_name = json_data.get("FromName", "")
    from_email = json_data.get("From", "")
    from_header = f"{from_name} <{from_email}>" if from_name and from_email else str(from_email or from_name)

    reply_to_header = str(json_data.get("ReplyTo", ""))
    text_body = str(json_data.get("TextBody", ""))
    html_body = str(json_data.get("HtmlBody", ""))

    headers_list = json_data.get("Headers", [])
    headers_lines = []
    if isinstance(headers_list, list):
        for h in headers_list:
            if isinstance(h, dict) and h.get("Name") and h.get("Value"):
                headers_lines.append(f"{h['Name']}: {h['Value']}")
    headers_blob = "\r\n".join(headers_lines)

    raw_email = json_data.get("RawEmail", "")
    has_raw = bool(raw_email)
    if has_raw:
        raw_bytes = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
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
        provider_metadata={
            "provider": "postmark",
            "message_id": json_data.get("MessageID"),
            "tag": json_data.get("Tag"),
        },
    )
