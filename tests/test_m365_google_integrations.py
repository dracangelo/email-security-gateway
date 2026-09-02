"""
Unit tests for Microsoft 365 and Google Workspace integration API clients.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from webhook_receiver.m365_client import M365GraphClient
from webhook_receiver.google_client import GoogleWorkspaceClient


@pytest.mark.anyio
async def test_m365_graph_client():
    client = M365GraphClient(tenant_id="test-tenant", client_id="cid", client_secret="sec")

    # Mock OAuth token
    mock_resp_token = MagicMock()
    mock_resp_token.status_code = 200
    mock_resp_token.raise_for_status = lambda: None
    mock_resp_token.json.return_value = {"access_token": "token_m365_123"}

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp_token
        token = await client.get_access_token()
        assert token == "token_m365_123"

    # Mock get_message_mime
    mock_resp_mime = MagicMock()
    mock_resp_mime.status_code = 200
    mock_resp_mime.raise_for_status = lambda: None
    mock_resp_mime.content = b"From: alice@example.com\r\nTo: bob@example.com\r\n\r\nMIME test"

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_mime
        mime = await client.get_message_mime("user123", "msg456")
        assert b"MIME test" in mime

    # Mock move_to_junk
    mock_resp_junk = MagicMock()
    mock_resp_junk.status_code = 200
    mock_resp_junk.raise_for_status = lambda: None
    mock_resp_junk.json.return_value = {"id": "msg456", "folder": "junkemail"}

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp_junk
        res = await client.move_to_junk("user123", "msg456")
        assert res["folder"] == "junkemail"

    # Mock delete_message
    mock_resp_del = MagicMock()
    mock_resp_del.status_code = 204

    with patch.object(httpx.AsyncClient, "delete", new_callable=AsyncMock) as mock_delete:
        mock_delete.return_value = mock_resp_del
        deleted = await client.delete_message("user123", "msg456")
        assert deleted is True


@pytest.mark.anyio
async def test_google_workspace_client():
    client = GoogleWorkspaceClient(service_account_email="sa@proj.iam.gserviceaccount.com")

    token = await client.get_access_token()
    assert token is not None

    # Mock get_message_raw
    import base64
    raw_encoded = base64.urlsafe_b64encode(b"From: g@example.com\r\n\r\nGoogle Raw").decode("utf-8")
    mock_resp_raw = MagicMock()
    mock_resp_raw.status_code = 200
    mock_resp_raw.raise_for_status = lambda: None
    mock_resp_raw.json.return_value = {"raw": raw_encoded}

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_raw
        raw = await client.get_message_raw("user@example.com", "msg789")
        assert b"Google Raw" in raw

    # Mock move_to_spam
    mock_resp_spam = MagicMock()
    mock_resp_spam.status_code = 200
    mock_resp_spam.raise_for_status = lambda: None
    mock_resp_spam.json.return_value = {"id": "msg789", "labelIds": ["SPAM"]}

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp_spam
        res = await client.move_to_spam("user@example.com", "msg789")
        assert "SPAM" in res["labelIds"]

    # Mock delete_message
    mock_resp_trash = MagicMock()
    mock_resp_trash.status_code = 200

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp_trash
        deleted = await client.delete_message("user@example.com", "msg789")
        assert deleted is True
