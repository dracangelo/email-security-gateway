"""Pulls attachment parts out of a raw RFC 5322 / MIME message."""
from __future__ import annotations

from email import message_from_bytes
from email.message import Message

from .models import Attachment


def extract_attachments(raw_message: bytes) -> list[Attachment]:
    """
    Walks every MIME part. A part counts as an attachment if it's
    explicitly marked Content-Disposition: attachment, OR it carries a
    filename with no disposition set at all -- some mail clients omit
    Content-Disposition entirely for what's unambiguously an attachment,
    and treating "has a filename" as sufficient avoids missing those.
    """
    try:
        msg = message_from_bytes(raw_message)
    except Exception:
        return []  # malformed message -- nothing to extract, not a crash

    if not msg.is_multipart():
        return []

    attachments: list[Attachment] = []
    part: Message
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        if disposition != "attachment" and not filename:
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if not payload:
            continue
        attachments.append(
            Attachment(filename=filename or "unnamed-attachment", content_type=part.get_content_type(), data=payload)
        )
    return attachments
