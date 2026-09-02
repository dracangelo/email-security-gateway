"""
Google Workspace / Gmail Pub/Sub push notification payload parser.
"""
from __future__ import annotations

import base64
import json
from .base import ParsedInboundMessage


def parse_google_workspace_payload(json_data: dict) -> ParsedInboundMessage:
    """
    Parse a Google Workspace Gmail Pub/Sub notification or push payload into ParsedInboundMessage.
    """
    pubsub_msg = json_data.get("message", {})
    data_str = pubsub_msg.get("data", "")
    decoded_data = {}
    if data_str and isinstance(data_str, str):
        try:
            raw_decoded = base64.b64decode(data_str).decode("utf-8")
            decoded_data = json.loads(raw_decoded)
        except Exception:
            decoded_data = {}

    email_details = json_data.get("emailDetails") or json_data.get("email_details") or decoded_data

    envelope_from = str(email_details.get("sender") or email_details.get("from_address") or decoded_data.get("emailAddress", ""))
    
    recipient = email_details.get("recipient") or email_details.get("to_address")
    if isinstance(recipient, list):
        envelope_to = [str(r) for r in recipient]
    elif recipient:
        envelope_to = [str(recipient)]
    else:
        envelope_to = [str(decoded_data.get("emailAddress"))] if decoded_data.get("emailAddress") else []

    from_header = str(email_details.get("from") or email_details.get("from_header") or envelope_from)
    reply_to_header = str(email_details.get("reply_to") or email_details.get("reply-to") or "")
    text_body = str(email_details.get("text") or email_details.get("body_plain") or "")
    html_body = str(email_details.get("html") or email_details.get("body_html") or "")
    headers_blob = str(email_details.get("headers") or "")

    raw_mime = email_details.get("raw") or json_data.get("raw")
    has_raw = bool(raw_mime)
    if has_raw:
        raw_bytes = raw_mime.encode("utf-8") if isinstance(raw_mime, str) else raw_mime
    else:
        raw_bytes = (headers_blob + "\r\n\r\n" + (text_body or html_body)).encode("utf-8", errors="replace")

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
            "provider": "google_workspace",
            "history_id": decoded_data.get("historyId"),
            "email_address": decoded_data.get("emailAddress"),
            "pubsub_message_id": pubsub_msg.get("messageId"),
        },
    )
