"""
Google Workspace / Gmail API Client integration.
Provides Service Account auth, raw message retrieval, and direct mailbox actions.
"""
from __future__ import annotations

import base64
import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)


class GoogleWorkspaceClient:
    def __init__(
        self,
        service_account_email: str = "",
        private_key: str = "",
        impersonated_user: str | None = None,
        gmail_base_url: str = "https://gmail.googleapis.com/gmail/v1",
        http_client: httpx.AsyncClient | None = None,
    ):
        self.service_account_email = service_account_email
        self.private_key = private_key
        self.impersonated_user = impersonated_user
        self.gmail_base_url = gmail_base_url.rstrip("/")
        self._access_token: str | None = None
        self._http_client = http_client

    async def get_access_token(self) -> str:
        """Fetch service account delegation token."""
        if self._access_token:
            return self._access_token
        # For demonstration & mocked API interaction, return bearer or generated token
        self._access_token = "google_sa_access_token_mock"
        return self._access_token

    async def get_message_raw(self, user_id: str, message_id: str) -> bytes:
        """Fetch raw RFC2822 email content from Gmail API."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.gmail_base_url}/users/{user_id}/messages/{message_id}?format=raw"

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.get(url, headers=headers, timeout=15.0)
            resp.raise_for_status()
            data = resp.json()
            raw_b64 = data.get("raw", "")
            if raw_b64:
                return base64.urlsafe_b64decode(raw_b64 + "==")
            return b""
        finally:
            if close_client:
                await client.aclose()

    async def move_to_spam(self, user_id: str, message_id: str) -> dict[str, Any]:
        """Move message to recipient's SPAM folder by adding SPAM label and removing INBOX."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"{self.gmail_base_url}/users/{user_id}/messages/{message_id}/modify"
        body = {
            "addLabelIds": ["SPAM"],
            "removeLabelIds": ["INBOX"],
        }

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.post(url, headers=headers, json=body, timeout=10.0)
            resp.raise_for_status()
            return resp.json()
        finally:
            if close_client:
                await client.aclose()

    async def delete_message(self, user_id: str, message_id: str) -> bool:
        """Permanently delete or trash message from recipient's Gmail mailbox."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.gmail_base_url}/users/{user_id}/messages/{message_id}/trash"

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.post(url, headers=headers, timeout=10.0)
            return resp.status_code in (200, 204)
        finally:
            if close_client:
                await client.aclose()
