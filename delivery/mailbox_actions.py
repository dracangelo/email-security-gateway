"""
Unified Direct Mailbox Action service for post-delivery operations.
Provides a single interface to execute Junk move, deletion ("zap"), or tagging on
Microsoft 365 / Exchange Online and Google Workspace mailboxes.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class DirectMailboxService:
    def __init__(
        self,
        m365_client: Optional[M365GraphClient] = None,
        google_client: Optional[GoogleWorkspaceClient] = None,
    ):
        self.m365_client = m365_client
        self.google_client = google_client

    async def move_to_junk(self, provider: str, user_id: str, message_id: str) -> Dict[str, Any]:
        """Move a delivered email to the recipient's Junk/Spam folder."""
        provider_key = provider.lower()
        if provider_key in ("m365", "graph", "microsoft"):
            if not self.m365_client:
                logger.warning("M365 client not configured; simulating move_to_junk for %s/%s", user_id, message_id)
                return {"status": "simulated", "provider": "m365", "action": "move_to_junk"}
            return await self.m365_client.move_to_junk(user_id=user_id, message_id=message_id)

        elif provider_key in ("google", "workspace", "gmail"):
            if not self.google_client:
                logger.warning("Google client not configured; simulating move_to_junk for %s/%s", user_id, message_id)
                return {"status": "simulated", "provider": "google", "action": "move_to_junk"}
            res = await self.google_client.trash_message(user_id=user_id, message_id=message_id)
            return {"status": "success" if res else "failed", "provider": "google", "action": "move_to_junk"}

        else:
            raise ValueError(f"Unsupported mailbox provider: {provider}")

    async def delete_message(self, provider: str, user_id: str, message_id: str) -> bool:
        """Permanently delete / zap a delivered message from recipient's mailbox."""
        provider_key = provider.lower()
        if provider_key in ("m365", "graph", "microsoft"):
            if not self.m365_client:
                logger.warning("M365 client not configured; simulating delete_message for %s/%s", user_id, message_id)
                return True
            return await self.m365_client.delete_message(user_id=user_id, message_id=message_id)

        elif provider_key in ("google", "workspace", "gmail"):
            if not self.google_client:
                logger.warning("Google client not configured; simulating delete_message for %s/%s", user_id, message_id)
                return True
            return await self.google_client.delete_message(user_id=user_id, message_id=message_id)

        else:
            raise ValueError(f"Unsupported mailbox provider: {provider}")
