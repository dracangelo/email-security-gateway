"""
Microsoft 365 / Exchange Online Graph API payload parser.
"""
from __future__ import annotations

from .base import ParsedInboundMessage


def parse_m365_graph_payload(json_data: dict) -> ParsedInboundMessage:
    """
    Parse a Microsoft 365 Graph notification payload into ParsedInboundMessage.
    Supports Graph notification objects with resourceData or journal wrapper structures.
    """
    value = json_data.get("value", [])
    item = value[0] if isinstance(value, list) and value else json_data
    if not isinstance(item, dict):
        item = {}

    resource_data = item.get("resourceData", item)
    if not isinstance(resource_data, dict):
        resource_data = {}

    # Extract sender / envelope from
    sender_obj = resource_data.get("sender", {}).get("emailAddress", {}) if isinstance(resource_data.get("sender"), dict) else {}
    from_obj = resource_data.get("from", {}).get("emailAddress", {}) if isinstance(resource_data.get("from"), dict) else {}
    
    envelope_from = str(sender_obj.get("address") or from_obj.get("address") or resource_data.get("from_address", ""))
    
    # Extract envelope to / recipients
    envelope_to: list[str] = []
    to_recipients = resource_data.get("toRecipients", [])
    if isinstance(to_recipients, list):
        for r in to_recipients:
            if isinstance(r, dict):
                addr = r.get("emailAddress", {}).get("address") if isinstance(r.get("emailAddress"), dict) else None
                if addr:
                    envelope_to.append(str(addr))
    if not envelope_to and resource_data.get("to_address"):
        envelope_to = [str(resource_data["to_address"])]

    from_name = from_obj.get("name", "")
    from_addr = from_obj.get("address", envelope_from)
    from_header = f"{from_name} <{from_addr}>" if from_name and from_addr else str(from_addr)

    # Reply-To
    reply_to_list = resource_data.get("replyTo", [])
    reply_to_addrs = []
    if isinstance(reply_to_list, list):
        for r in reply_to_list:
            if isinstance(r, dict):
                addr = r.get("emailAddress", {}).get("address") if isinstance(r.get("emailAddress"), dict) else None
                if addr:
                    reply_to_addrs.append(str(addr))
    reply_to_header = ", ".join(reply_to_addrs)

    # Body
    body_obj = resource_data.get("body", {})
    text_body = ""
    html_body = ""
    if isinstance(body_obj, dict):
        content_type = str(body_obj.get("contentType", "")).lower()
        content = str(body_obj.get("content", ""))
        if "html" in content_type:
            html_body = content
        else:
            text_body = content

    # Headers
    headers_list = resource_data.get("internetMessageHeaders", [])
    headers_lines = []
    if isinstance(headers_list, list):
        for h in headers_list:
            if isinstance(h, dict) and h.get("name") and h.get("value"):
                headers_lines.append(f"{h['name']}: {h['value']}")
    headers_blob = "\r\n".join(headers_lines)

    # Raw MIME or content
    raw_mime = resource_data.get("mimeContent") or item.get("mimeContent")
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
            "provider": "m365_graph",
            "subscription_id": item.get("subscriptionId"),
            "message_id": resource_data.get("id") or item.get("resource"),
            "tenant_id": item.get("tenantId"),
        },
    )
