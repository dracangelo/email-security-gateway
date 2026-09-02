"""
Retroactive Removal ("Auto-Zap") Engine.
Tracks delivered message metadata and mailbox locations to automatically purge
emails across all recipients when post-delivery threat intelligence or Time-of-Click
scanning confirms a URL or attachment is malicious.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

from delivery.mailbox_actions import DirectMailboxService

logger = logging.getLogger(__name__)


@dataclass
class DeliveredMessageRecord:
    message_id: str
    recipients: List[Tuple[str, str, str]]  # list of (provider, user_id, provider_message_id)
    urls: List[str] = field(default_factory=list)
    attachment_hashes: List[str] = field(default_factory=list)
    content_hash: str = ""
    delivered_at: float = field(default_factory=time.time)
    zapped: bool = False
    zap_reason: str = ""


class RetroactiveZapEngine:
    def __init__(self, mailbox_service: Optional[DirectMailboxService] = None):
        self.mailbox_service = mailbox_service or DirectMailboxService()
        self._records: Dict[str, DeliveredMessageRecord] = {}

    def register_delivery(
        self,
        message_id: str,
        recipients: List[Tuple[str, str, str]],
        urls: Optional[List[str]] = None,
        attachment_hashes: Optional[List[str]] = None,
        content_hash: str = "",
    ) -> None:
        """Register a delivered email for potential retroactive removal."""
        record = DeliveredMessageRecord(
            message_id=message_id,
            recipients=recipients,
            urls=urls or [],
            attachment_hashes=attachment_hashes or [],
            content_hash=content_hash,
        )
        self._records[message_id] = record
        logger.info("Registered message %s for auto-zap tracking (%d recipients)", message_id, len(recipients))

    async def trigger_zap_by_url(self, target_url: str, reason: str = "URL weaponized post-delivery") -> List[str]:
        """Find all delivered emails containing the specified target URL and purge them from mailboxes."""
        zapped_ids = []
        for msg_id, rec in list(self._records.items()):
            if rec.zapped:
                continue
            if any(target_url in u or u in target_url for u in rec.urls):
                success = await self._execute_zap(rec, reason)
                if success:
                    zapped_ids.append(msg_id)
        return zapped_ids

    async def trigger_zap_by_hash(self, file_hash: str, reason: str = "Attachment confirmed malicious post-delivery") -> List[str]:
        """Find all delivered emails containing the specified attachment hash and purge them from mailboxes."""
        target_hash = file_hash.lower()
        zapped_ids = []
        for msg_id, rec in list(self._records.items()):
            if rec.zapped:
                continue
            if any(h.lower() == target_hash for h in rec.attachment_hashes):
                success = await self._execute_zap(rec, reason)
                if success:
                    zapped_ids.append(msg_id)
        return zapped_ids

    async def trigger_zap_by_message_id(self, message_id: str, reason: str = "Manual admin zap request") -> bool:
        """Purge a specific delivered email by message ID."""
        rec = self._records.get(message_id)
        if not rec or rec.zapped:
            return False
        return await self._execute_zap(rec, reason)

    async def _execute_zap(self, record: DeliveredMessageRecord, reason: str) -> bool:
        """Executes mailbox deletion calls across all recipient mailboxes for a record."""
        logger.warning("Triggering retroactive zap for message %s: %s", record.message_id, reason)
        overall_success = True
        for provider, user_id, provider_msg_id in record.recipients:
            try:
                ok = await self.mailbox_service.delete_message(provider, user_id, provider_msg_id)
                if not ok:
                    overall_success = False
            except Exception as exc:
                logger.error("Failed to zap message %s in mailbox %s/%s: %s", record.message_id, provider, user_id, exc)
                overall_success = False

        record.zapped = overall_success
        record.zap_reason = reason
        return overall_success

    def get_stats(self) -> Dict[str, int]:
        total = len(self._records)
        zapped = sum(1 for r in self._records.values() if r.zapped)
        return {"tracked_messages": total, "zapped_messages": zapped}
