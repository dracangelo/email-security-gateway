"""
Microsoft 365 / Exchange Online Graph API Client integration.
Provides OAuth token management, message MIME retrieval, and direct mailbox actions.
"""
from __future__ import annotations

import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)


class M365GraphClient:
    def __init__(
        self,
        tenant_id: str = "common",
        client_id: str = "",
        client_secret: str = "",
        token_url: str | None = None,
        graph_base_url: str = "https://graph.microsoft.com/v1.0",
        http_client: httpx.AsyncClient | None = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url or f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.graph_base_url = graph_base_url.rstrip("/")
        self._access_token: str | None = None
        self._http_client = http_client

    async def get_access_token(self) -> str:
        """Fetch or reuse client credentials access token."""
        if self._access_token:
            return self._access_token

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            token_data = resp.json()
            self._access_token = token_data.get("access_token", "")
            return self._access_token or ""
        finally:
            if close_client:
                await client.aclose()

    async def get_message_mime(self, user_id: str, message_id: str) -> bytes:
        """Retrieve raw MIME content ($value) for a message."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.graph_base_url}/users/{user_id}/messages/{message_id}/$value"

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.get(url, headers=headers, timeout=15.0)
            resp.raise_for_status()
            return resp.content
        finally:
            if close_client:
                await client.aclose()

    async def move_to_junk(self, user_id: str, message_id: str) -> dict[str, Any]:
        """Move message to recipient's Junk Email folder."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"{self.graph_base_url}/users/{user_id}/messages/{message_id}/move"

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.post(url, headers=headers, json={"destinationId": "junkemail"}, timeout=10.0)
            resp.raise_for_status()
            return resp.json()
        finally:
            if close_client:
                await client.aclose()

    async def delete_message(self, user_id: str, message_id: str) -> bool:
        """Delete message directly from recipient's mailbox (retroactive zap)."""
        token = await self.get_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self.graph_base_url}/users/{user_id}/messages/{message_id}"

        client = self._http_client or httpx.AsyncClient()
        close_client = self._http_client is None
        try:
            resp = await client.delete(url, headers=headers, timeout=10.0)
            return resp.status_code in (200, 204)
        finally:
            if close_client:
                await client.aclose()
