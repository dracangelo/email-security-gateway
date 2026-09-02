"""
Provider-agnostic data model for parsed inbound webhook email payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedInboundMessage:
    envelope_from: str
    envelope_to: list[str]
    from_header: str = ""
    reply_to_header: str = ""
    text_body: str = ""
    html_body: str = ""
    headers_blob: str = ""
    raw_message: bytes = b""
    has_raw_mime: bool = False
    provider_metadata: dict = field(default_factory=dict)
