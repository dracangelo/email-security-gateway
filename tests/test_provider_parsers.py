"""
Unit and integration tests for Multi-Provider Webhook Ingestion & Auth Abstraction:
- SendGrid, Mailgun, and AWS SES payload parsers
- Mailgun HMAC-SHA256 signature verification
- AWS SNS notification authentication
- FastAPI /webhooks/mailgun/inbound and /webhooks/aws/ses endpoints
"""
import hmac
import hashlib
import time
import json
import pytest
from fastapi.testclient import TestClient

from security.provider_auth import MailgunAuthStrategy, AWSSNSAuthStrategy
from security.webhook_auth import WebhookAuthError
from webhook_receiver.parsers import (
    parse_aws_ses_payload,
    parse_google_workspace_payload,
    parse_m365_graph_payload,
    parse_mailgun_payload,
    parse_postmark_payload,
    parse_sendgrid_payload,
)
from webhook_receiver.app import app


class TestMailgunAuthStrategy:
    def test_valid_mailgun_signature(self):
        timestamp = str(int(time.time()))
        token = "random_token_123"
        key = "key-secret-12345"

        sig = hmac.new(
            key.encode("utf-8"),
            f"{timestamp}{token}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        auth = MailgunAuthStrategy()
        auth.verify_signature(timestamp, token, sig, key)

    def test_invalid_mailgun_signature(self):
        timestamp = str(int(time.time()))
        token = "random_token_123"
        key = "key-secret-12345"
        bad_sig = "0000000000000000000000000000000000000000000000000000000000000000"

        auth = MailgunAuthStrategy()
        with pytest.raises(WebhookAuthError) as exc_info:
            auth.verify_signature(timestamp, token, bad_sig, key)
        assert exc_info.value.status_code == 401
        assert "invalid Mailgun HMAC signature" in str(exc_info.value)

    def test_expired_timestamp_mailgun(self):
        old_timestamp = str(int(time.time()) - 3600)  # 1 hour ago
        token = "random_token_123"
        key = "key-secret-12345"

        sig = hmac.new(
            key.encode("utf-8"),
            f"{old_timestamp}{token}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        auth = MailgunAuthStrategy()
        with pytest.raises(WebhookAuthError) as exc_info:
            auth.verify_signature(old_timestamp, token, sig, key)
        assert "timestamp expired" in str(exc_info.value)


class TestAWSSNSAuthStrategy:
    def test_valid_sns_message(self):
        msg = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-inbound",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-123.pem"
        }
        auth = AWSSNSAuthStrategy()
        auth.verify_sns_message(msg)

    def test_invalid_sns_cert_domain(self):
        msg = {
            "Type": "Notification",
            "SigningCertURL": "https://attacker.com/malicious.pem"
        }
        auth = AWSSNSAuthStrategy()
        with pytest.raises(WebhookAuthError) as exc_info:
            auth.verify_sns_message(msg)
        assert "invalid AWS SNS SigningCertURL domain" in str(exc_info.value)


class TestProviderParsers:
    def test_sendgrid_parser_raw_mime_detection(self):
        data_no_mime = {
            "from": "Alice <alice@example.com>",
            "text": "Hello world",
            "headers": "From: alice@example.com\r\nTo: bob@example.com\r\n"
        }
        parsed = parse_sendgrid_payload(data_no_mime)
        assert parsed.has_raw_mime is False
        assert parsed.from_header == "Alice <alice@example.com>"

        data_with_mime = {
            "from": "Alice <alice@example.com>",
            "email": "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nHello raw MIME"
        }
        parsed_mime = parse_sendgrid_payload(data_with_mime)
        assert parsed_mime.has_raw_mime is True
        assert b"Hello raw MIME" in parsed_mime.raw_message

    def test_mailgun_parser(self):
        data = {
            "sender": "alice@example.com",
            "recipient": "bob@example.com",
            "from": "Alice <alice@example.com>",
            "reply-to": "alice-reply@example.com",
            "body-plain": "Mailgun text content",
            "message-headers": "From: alice@example.com\r\nTo: bob@example.com"
        }
        parsed = parse_mailgun_payload(data)
        assert parsed.envelope_from == "alice@example.com"
        assert parsed.envelope_to == ["bob@example.com"]
        assert parsed.reply_to_header == "alice-reply@example.com"
        assert parsed.provider_metadata["provider"] == "mailgun"

    def test_aws_ses_parser(self):
        sns_msg = {
            "Type": "Notification",
            "Message": json.dumps({
                "mail": {
                    "source": "alice@example.com",
                    "destination": ["bob@example.com"],
                    "commonHeaders": {
                        "from": ["Alice <alice@example.com>"],
                        "replyTo": ["alice-reply@example.com"]
                    },
                    "headers": [
                        {"name": "From", "value": "Alice <alice@example.com>"},
                        {"name": "To", "value": "bob@example.com"}
                    ]
                },
                "content": "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nSES raw content"
            })
        }
        parsed = parse_aws_ses_payload(sns_msg)
        assert parsed.envelope_from == "alice@example.com"
        assert parsed.envelope_to == ["bob@example.com"]
        assert parsed.has_raw_mime is True
        assert b"SES raw content" in parsed.raw_message

    def test_postmark_parser(self):
        data = {
            "From": "alice@example.com",
            "FromName": "Alice",
            "ToFull": [{"Email": "bob@example.com"}],
            "TextBody": "Postmark body",
            "RawEmail": "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nPostmark raw",
            "MessageID": "pm-123",
        }
        parsed = parse_postmark_payload(data)
        assert parsed.envelope_from == "alice@example.com"
        assert parsed.envelope_to == ["bob@example.com"]
        assert parsed.has_raw_mime is True
        assert parsed.provider_metadata["provider"] == "postmark"

    def test_m365_graph_parser(self):
        data = {
            "value": [{
                "subscriptionId": "sub-99",
                "resourceData": {
                    "from": {"emailAddress": {"address": "alice@example.com", "name": "Alice"}},
                    "toRecipients": [{"emailAddress": {"address": "bob@example.com"}}],
                    "body": {"contentType": "text", "content": "M365 body"},
                    "mimeContent": "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nM365 raw",
                }
            }]
        }
        parsed = parse_m365_graph_payload(data)
        assert parsed.envelope_from == "alice@example.com"
        assert parsed.envelope_to == ["bob@example.com"]
        assert parsed.provider_metadata["provider"] == "m365_graph"

    def test_google_workspace_parser(self):
        data = {
            "emailDetails": {
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "text": "Google text",
                "raw": "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nGoogle raw",
            }
        }
        parsed = parse_google_workspace_payload(data)
        assert parsed.envelope_from == "alice@example.com"
        assert parsed.envelope_to == ["bob@example.com"]
        assert parsed.provider_metadata["provider"] == "google_workspace"


from unittest.mock import AsyncMock, patch
from auth_checker.models import AuthVerdict, DKIMResult, DKIMResultCode, DMARCPolicy, DMARCResult, DMARCResultCode, SPFResult, SPFResultCode
from content_analysis.models import ContentVerdict


def _clean_auth_verdict() -> AuthVerdict:
    return AuthVerdict(
        from_domain="example.com",
        spf=SPFResult(code=SPFResultCode.PASS, domain="example.com", client_ip="203.0.113.1"),
        dkim=DKIMResult(code=DKIMResultCode.PASS, signing_domain="example.com"),
        dmarc=DMARCResult(code=DMARCResultCode.PASS, policy=DMARCPolicy.NONE, record_found=True),
        score_delta=0,
        reasons=[],
    )


@patch("webhook_receiver.app.run_auth_checks")
@patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
def test_mailgun_inbound_endpoint(mock_analyze, mock_auth):
    mock_auth.return_value = _clean_auth_verdict()
    mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

    client = TestClient(app)
    response = client.post(
        "/webhooks/mailgun/inbound",
        data={
            "sender": "user@example.com",
            "recipient": "dest@example.com",
            "from": "User <user@example.com>",
            "body-plain": "Clean test email",
            "message-headers": "From: user@example.com\r\nTo: dest@example.com"
        }
    )
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["action"] == "forward"
    assert "decision" in res_data


@patch("webhook_receiver.app.run_auth_checks")
@patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
def test_aws_ses_inbound_endpoint(mock_analyze, mock_auth):
    mock_auth.return_value = _clean_auth_verdict()
    mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

    client = TestClient(app)
    payload = {
        "Type": "Notification",
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:ses-inbound",
        "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-123.pem",
        "Message": json.dumps({
            "mail": {
                "source": "sender@example.com",
                "destination": ["receiver@example.com"],
                "commonHeaders": {"from": ["sender@example.com"]},
                "headers": [{"name": "From", "value": "sender@example.com"}]
            },
            "content": "From: sender@example.com\r\nTo: receiver@example.com\r\n\r\nBody test"
        })
    }
    response = client.post("/webhooks/aws/ses", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["action"] == "forward"


@patch("webhook_receiver.app.run_auth_checks")
@patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
def test_postmark_inbound_endpoint(mock_analyze, mock_auth):
    mock_auth.return_value = _clean_auth_verdict()
    mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

    client = TestClient(app)
    payload = {
        "From": "sender@example.com",
        "To": "receiver@example.com",
        "TextBody": "Postmark test body",
    }
    response = client.post("/webhooks/postmark/inbound", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["action"] == "forward"


@patch("webhook_receiver.app.run_auth_checks")
@patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
def test_m365_graph_inbound_endpoint(mock_analyze, mock_auth):
    mock_auth.return_value = _clean_auth_verdict()
    mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

    client = TestClient(app)
    # Test validation token handshaking
    resp_val = client.post("/webhooks/m365/graph?validationToken=abc123token")
    assert resp_val.status_code == 200
    assert resp_val.text == "abc123token"

    payload = {
        "value": [{
            "resourceData": {
                "sender": {"emailAddress": {"address": "sender@example.com"}},
                "toRecipients": [{"emailAddress": {"address": "receiver@example.com"}}],
            }
        }]
    }
    response = client.post("/webhooks/m365/graph", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["action"] == "forward"


@patch("webhook_receiver.app.run_auth_checks")
@patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
def test_google_pubsub_inbound_endpoint(mock_analyze, mock_auth):
    mock_auth.return_value = _clean_auth_verdict()
    mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

    client = TestClient(app)
    payload = {
        "emailDetails": {
            "sender": "sender@example.com",
            "recipient": "receiver@example.com",
            "text": "Google test body",
        }
    }
    response = client.post("/webhooks/google/pubsub", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["action"] == "forward"


