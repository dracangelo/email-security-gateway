"""
AWS SES / SNS notification payload parser.
"""
from __future__ import annotations

import json
from .base import ParsedInboundMessage


def parse_aws_ses_payload(sns_body: dict) -> ParsedInboundMessage:
    raw_message_str = sns_body.get("Message", "{}")
    if isinstance(raw_message_str, str):
        try:
            msg = json.loads(raw_message_str)
        except json.JSONDecodeError:
            msg = {}
    else:
        msg = sns_body if isinstance(sns_body, dict) else {}

    mail = msg.get("mail", {})
    envelope_from = mail.get("source", "")
    envelope_to = mail.get("destination", [])

    common_headers = mail.get("commonHeaders", {})
    from_header = ", ".join(common_headers.get("from", [])) if isinstance(common_headers.get("from"), list) else str(common_headers.get("from", ""))
    reply_to_header = ", ".join(common_headers.get("replyTo", [])) if isinstance(common_headers.get("replyTo"), list) else str(common_headers.get("replyTo", ""))

    headers_list = mail.get("headers", [])
    headers_lines = [f"{h.get('name', '')}: {h.get('value', '')}" for h in headers_list if isinstance(h, dict)]
    headers_blob = "\r\n".join(headers_lines)

    content = msg.get("content", "")
    has_raw = bool(content)
    if content:
        raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
    else:
        raw_bytes = (headers_blob + "\r\n\r\n").encode("utf-8")

    return ParsedInboundMessage(
        envelope_from=envelope_from,
        envelope_to=envelope_to,
        from_header=from_header,
        reply_to_header=reply_to_header,
        text_body="",
        html_body="",
        headers_blob=headers_blob,
        raw_message=raw_bytes,
        has_raw_mime=has_raw,
        provider_metadata={"provider": "aws_ses", "message_id": mail.get("messageId")},
    )
