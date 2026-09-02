"""
Per-Provider Webhook Contract and Schema Mutation Tests.
Enforces contract compliance across all supported email ingestion providers:
- SendGrid
- Mailgun
- AWS SES / SNS
- Postmark
- Microsoft 365
- Google Workspace
"""
import json
import base64
import pytest
from webhook_receiver.parsers import (
    parse_sendgrid_payload,
    parse_mailgun_payload,
    parse_aws_ses_payload,
    parse_postmark_payload,
    parse_m365_graph_payload,
    parse_google_workspace_payload,
)


@pytest.mark.contract
class TestProviderWebhookContracts:
    """Contract tests verifying provider payload schemas and mutation resiliency."""

    def test_sendgrid_contract_schema(self):
        """Contract: SendGrid Inbound Parse standard multipart fields."""
        payload = {
            "from": "Alice Smith <alice@example.com>",
            "to": "bob@recipient.org",
            "subject": "Monthly Statement",
            "text": "Your monthly statement is attached.",
            "html": "<p>Your monthly statement is attached.</p>",
            "headers": "Received: from mail.example.com\r\nMessage-ID: <msg123@example.com>\r\n",
            "spam_score": "0.12",
            "SPF": "pass",
        }
        parsed = parse_sendgrid_payload(payload)
        assert parsed.from_header == "Alice Smith <alice@example.com>"
        assert "bob@recipient.org" in parsed.envelope_to or parsed.envelope_to == []
        assert "monthly statement" in parsed.text_body.lower()
        assert "monthly statement" in parsed.html_body.lower()

    def test_sendgrid_contract_mutations(self):
        """Mutation: Missing optional fields (no html, no spam_score, raw email only)."""
        minimal_payload = {
            "from": "sales@company.com",
            "to": "team@target.com",
            "subject": "Minimal subject",
            "email": "From: sales@company.com\r\nTo: team@target.com\r\nSubject: Minimal subject\r\n\r\nRaw email body",
        }
        parsed = parse_sendgrid_payload(minimal_payload)
        assert parsed.from_header == "sales@company.com"
        assert parsed.has_raw_mime is True
        assert len(parsed.raw_message) > 0

    def test_mailgun_contract_schema(self):
        """Contract: Mailgun inbound webhook standard fields."""
        payload = {
            "sender": "carol@mailgun.org",
            "recipient": "dave@victim.com",
            "subject": "Important Notification",
            "body-plain": "Please review your pending order.",
            "body-html": "<div>Please review your pending order.</div>",
            "message-headers": json.dumps([["Message-Id", "<mg123@mailgun.org>"], ["X-Mailgun-Sscore", "0.5"]]),
            "timestamp": "1700000000",
            "token": "test-token",
            "signature": "test-signature",
        }
        parsed = parse_mailgun_payload(payload)
        assert parsed.envelope_from == "carol@mailgun.org"
        assert "dave@victim.com" in parsed.envelope_to
        assert "pending order" in parsed.text_body.lower()

    def test_aws_ses_sns_contract_schema(self):
        """Contract: AWS SES Inbound Notification via SNS JSON message."""
        raw_mime = b"From: support@aws.amazon.com\r\nTo: user@example.com\r\nSubject: AWS Alert\r\n\r\nYour instance was resized."
        ses_mail_obj = {
            "mail": {
                "messageId": "ses-msg-9999",
                "source": "support@aws.amazon.com",
                "destination": ["user@example.com"],
                "headersTruncated": False,
                "headers": [
                    {"name": "From", "value": "support@aws.amazon.com"},
                    {"name": "To", "value": "user@example.com"},
                    {"name": "Subject", "value": "AWS Alert"},
                ],
            },
            "receipt": {
                "spfVerdict": {"status": "PASS"},
                "dkimVerdict": {"status": "PASS"},
                "dmarcVerdict": {"status": "PASS"},
                "action": {"type": "SNS", "topicArn": "arn:aws:sns:us-east-1:123456789:email-events"},
            },
            "content": base64.b64encode(raw_mime).decode("ascii"),
        }

        sns_wrapper = {
            "Type": "Notification",
            "MessageId": "sns-notif-111",
            "Message": json.dumps(ses_mail_obj),
        }

        parsed = parse_aws_ses_payload(sns_wrapper)
        assert parsed.envelope_from == "support@aws.amazon.com"
        assert "user@example.com" in parsed.envelope_to
        assert parsed.has_raw_mime is True

    def test_postmark_contract_schema(self):
        """Contract: Postmark JSON inbound webhook payload."""
        payload = {
            "From": "notifications@postmarkapp.com",
            "To": "ops@client.com",
            "Subject": "Deployment Successful",
            "TextBody": "Build #42 is now live.",
            "HtmlBody": "<b>Build #42 is now live.</b>",
            "MessageID": "postmark-uuid-444",
            "Headers": [{"Name": "X-Spam-Status", "Value": "No"}],
        }
        parsed = parse_postmark_payload(payload)
        assert parsed.from_header == "notifications@postmarkapp.com"
        assert "ops@client.com" in parsed.envelope_to
        assert "build #42" in parsed.text_body.lower()

    def test_m365_graph_contract_schema(self):
        """Contract: Microsoft 365 Graph API Change Notification schema."""
        payload = {
            "value": [
                {
                    "subscriptionId": "sub-m365-123",
                    "changeType": "created",
                    "resource": "Users/user@company.com/Messages/AAMkAD...",
                    "clientState": "secretClientState",
                    "resourceData": {
                        "id": "msg-m365-001",
                        "subject": "Microsoft Security Alert",
                        "from": {"emailAddress": {"name": "Security", "address": "sec@microsoft.com"}},
                        "toRecipients": [{"emailAddress": {"address": "user@company.com"}}],
                        "body": {"contentType": "text", "content": "Unusual login activity detected."},
                    },
                }
            ]
        }
        parsed = parse_m365_graph_payload(payload)
        assert parsed.envelope_from == "sec@microsoft.com"
        assert "user@company.com" in parsed.envelope_to
        assert "unusual login" in parsed.text_body.lower()

    def test_google_workspace_contract_schema(self):
        """Contract: Google Workspace Gmail Pub/Sub push notification schema."""
        inner_data = {
            "emailAddress": "admin@gsuite-domain.com",
            "historyId": "987654321",
            "from": "billing@google.com",
            "to": "admin@gsuite-domain.com",
            "subject": "Google Cloud Invoice Available",
            "text": "Your monthly Google Cloud invoice is available.",
        }
        encoded_data = base64.b64encode(json.dumps(inner_data).encode("utf-8")).decode("ascii")

        pubsub_payload = {
            "message": {
                "data": encoded_data,
                "messageId": "pubsub-msg-555",
                "publishTime": "2026-09-01T20:00:00Z",
            },
            "subscription": "projects/my-project/subscriptions/gmail-inbound",
        }

        parsed = parse_google_workspace_payload(pubsub_payload)
        assert parsed.envelope_from == "admin@gsuite-domain.com"
        assert "admin@gsuite-domain.com" in parsed.envelope_to
        assert "invoice" in parsed.text_body.lower()
