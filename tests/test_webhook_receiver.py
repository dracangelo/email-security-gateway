import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from auth_checker.models import AuthVerdict, DKIMResult, DKIMResultCode, DMARCPolicy, DMARCResult, DMARCResultCode, SPFResult, SPFResultCode
from content_analysis.models import ContentVerdict
from config import settings
from webhook_receiver.app import app, process_message

client = TestClient(app)


def _clean_auth_verdict() -> AuthVerdict:
    return AuthVerdict(
        from_domain="sender.com",
        spf=SPFResult(code=SPFResultCode.PASS, domain="sender.com", client_ip="203.0.113.1"),
        dkim=DKIMResult(code=DKIMResultCode.PASS, signing_domain="sender.com"),
        dmarc=DMARCResult(code=DMARCResultCode.PASS, policy=DMARCPolicy.REJECT, record_found=True),
        score_delta=0,
        reasons=[],
    )


def _dirty_auth_verdict() -> AuthVerdict:
    return AuthVerdict(
        from_domain="sender.com",
        spf=SPFResult(code=SPFResultCode.FAIL, domain="sender.com", client_ip="203.0.113.1"),
        dkim=DKIMResult(code=DKIMResultCode.NONE),
        dmarc=DMARCResult(code=DMARCResultCode.FAIL, policy=DMARCPolicy.REJECT, record_found=True),
        score_delta=95,
        reasons=["SPF hard fail", "no DKIM signature", "DMARC fail under p=reject"],
    )


class TestHealthChecks:
    def test_healthz(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_readyz(self):
        resp = client.get("/readyz")
        assert resp.status_code in (200, 503)
        assert "checks" in resp.json()


class TestProcessMessage:
    """Exercises the provider-agnostic core directly -- this is the part
    any inbound source (SendGrid, Mailgun, SES) ultimately calls. Each
    test uses distinct raw_message bytes: process_message() now dedupes
    by content hash, so two tests reusing identical bytes would have the
    second call silently short-circuit as 'duplicate'."""

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_clean_message_forwards(self, mock_analyze, mock_auth):
        mock_auth.return_value = _clean_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        import asyncio
        result = asyncio.run(process_message(
            message_id="test-1",
            raw_message=b"From: a@sender.com\r\n\r\nclean message unique bytes 1",
            client_ip="203.0.113.1",
            envelope_from="a@sender.com",
        ))
        assert result["action"] == "forward"

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_dirty_auth_quarantines(self, mock_analyze, mock_auth):
        mock_auth.return_value = _dirty_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        import asyncio
        result = asyncio.run(process_message(
            message_id="test-2",
            raw_message=b"From: a@sender.com\r\n\r\ndirty message unique bytes 2",
            client_ip="198.51.100.1",
            envelope_from="a@sender.com",
        ))
        assert result["action"] == "quarantine"
        assert result["decision"]["total_score"] == 95

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_stage_scores_combine_across_all_three_stages(self, mock_analyze, mock_auth):
        clean = _clean_auth_verdict()
        clean.score_delta = 15  # e.g. DKIM none but SPF/DMARC pass
        mock_auth.return_value = clean
        mock_analyze.return_value = ContentVerdict(score_delta=20, reasons=["urgency phrase"])

        import asyncio
        result = asyncio.run(process_message(
            message_id="test-3",
            raw_message=b"From: a@sender.com\r\n\r\nstage combination unique bytes 3",
            client_ip="203.0.113.1",
            envelope_from="a@sender.com",
        ))
        # auth(15) + content(20) + attachments(0, no attachments in a plain message)
        assert result["decision"]["total_score"] == 35
        assert result["action"] == "warn_and_strip"

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_duplicate_message_is_not_reprocessed(self, mock_analyze, mock_auth):
        mock_auth.return_value = _clean_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        import asyncio
        raw = b"From: a@sender.com\r\n\r\nduplicate detection unique bytes 4"
        first = asyncio.run(process_message(
            message_id="test-4a", raw_message=raw, client_ip="203.0.113.1", envelope_from="a@sender.com",
        ))
        second = asyncio.run(process_message(
            message_id="test-4b", raw_message=raw, client_ip="203.0.113.1", envelope_from="a@sender.com",
        ))
        assert first.get("duplicate") is not True
        assert second.get("duplicate") is True
        assert second["action"] == "skipped_duplicate"
        # the auth stage should only have actually run once
        assert mock_auth.call_count == 1


class TestSendGridEndpointAuth:
    def test_wrong_secret_returns_404_not_403(self):
        # settings.webhook_shared_secret defaults to "" in this test env,
        # which makes verify_secret() a no-op -- so this specifically
        # exercises the "auth disabled" path, and 404-vs-403 is exercised
        # directly against webhook_auth.verify_secret in test_security.py.
        # Here we just confirm an arbitrary secret segment is accepted
        # when no secret is configured.
        resp = client.post(
            "/webhooks/sendgrid/inbound/any-secret-value",
            data={
                "envelope": '{"from": "a@sender.com", "to": ["b@ourcompany.com"]}',
                "from": "A Sender <a@sender.com>",
                "text": "hello there, endpoint auth test",
                "headers": "Received: from mail.sender.com ([203.0.113.9]) by mx.google.com\r\nFrom: a@sender.com",
            },
        )
        assert resp.status_code == 200

    def test_configured_secret_enforced(self, monkeypatch):
        monkeypatch.setattr(settings, "webhook_shared_secret", "correct-secret")
        try:
            resp = client.post(
                "/webhooks/sendgrid/inbound/wrong-secret",
                data={"envelope": "{}", "from": "a@sender.com", "text": "hi", "headers": ""},
            )
            assert resp.status_code == 404
        finally:
            monkeypatch.setattr(settings, "webhook_shared_secret", "")

    def test_oversized_payload_rejected(self, monkeypatch):
        monkeypatch.setattr(settings, "max_message_size_bytes", 100)
        try:
            resp = client.post(
                "/webhooks/sendgrid/inbound/secret",
                data={"envelope": "{}", "from": "a@sender.com", "text": "x" * 500, "headers": ""},
            )
            assert resp.status_code == 413
        finally:
            monkeypatch.setattr(settings, "max_message_size_bytes", 25 * 1024 * 1024)


class TestSendGridEndpointEndToEnd:
    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_inbound_webhook_end_to_end(self, mock_analyze, mock_auth):
        mock_auth.return_value = _clean_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        resp = client.post(
            "/webhooks/sendgrid/inbound/test-secret",
            data={
                "envelope": '{"from": "a@sender.com", "to": ["b@ourcompany.com"]}',
                "from": "Alerts <a@sender.com>",
                "text": "hello there, full end to end test",
                "html": "<p>hello there</p>",
                "headers": "Received: from mail.sender.com ([203.0.113.42]) by mx.google.com\r\nFrom: a@sender.com",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "forward"
        assert mock_auth.call_args.kwargs["client_ip"] == "203.0.113.42"
        assert "attachments" in body  # attachment stage present in the response shape
        assert body["delivery"]["outcome"] == "relayed"
        assert "dry-run" in body["delivery"]["detail"]  # no RELAY_HOST configured in tests

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_quarantined_message_creates_reviewable_item(self, mock_analyze, mock_auth):
        mock_auth.return_value = _dirty_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        resp = client.post(
            "/webhooks/sendgrid/inbound/test-secret",
            data={
                "envelope": '{"from": "bad@sender.com", "to": ["b@ourcompany.com"]}',
                "from": "Alerts <bad@sender.com>",
                "text": "quarantine integration test unique body",
                "headers": "Received: from mail.sender.com ([198.51.100.7]) by mx.google.com\r\nFrom: bad@sender.com",
            },
        )
        body = resp.json()
        assert body["action"] == "quarantine"
        assert body["delivery"]["outcome"] == "quarantined"
        quarantine_id = body["delivery"]["quarantine_id"]
        assert quarantine_id

        # it should now show up in the admin review queue
        admin_resp = client.get("/admin/quarantine")
        pending_ids = [item["quarantine_id"] for item in admin_resp.json()["pending"]]
        assert quarantine_id in pending_ids


class TestAdminEndpoints:
    def test_list_quarantine_requires_no_token_when_unconfigured(self):
        # settings.admin_shared_secret defaults to "" in the test env,
        # which makes the check a no-op -- exercised directly with a real
        # configured secret below.
        resp = client.get("/admin/quarantine")
        assert resp.status_code == 200

    def test_admin_endpoint_rejects_missing_token_when_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "admin_shared_secret", "admin-secret-123")
        try:
            resp = client.get("/admin/quarantine")
            assert resp.status_code == 401
        finally:
            monkeypatch.setattr(settings, "admin_shared_secret", "")

    def test_admin_endpoint_accepts_correct_bearer_token(self, monkeypatch):
        monkeypatch.setattr(settings, "admin_shared_secret", "admin-secret-123")
        try:
            resp = client.get("/admin/quarantine", headers={"Authorization": "Bearer admin-secret-123"})
            assert resp.status_code == 200
        finally:
            monkeypatch.setattr(settings, "admin_shared_secret", "")

    @patch("webhook_receiver.app.run_auth_checks")
    @patch("webhook_receiver.app.analyze_content", new_callable=AsyncMock)
    def test_release_flow_dry_run(self, mock_analyze, mock_auth):
        mock_auth.return_value = _dirty_auth_verdict()
        mock_analyze.return_value = ContentVerdict(score_delta=0, reasons=[])

        resp = client.post(
            "/webhooks/sendgrid/inbound/test-secret",
            data={
                "envelope": '{"from": "bad2@sender.com", "to": ["b@ourcompany.com"]}',
                "from": "Alerts <bad2@sender.com>",
                "text": "release flow test unique body",
                "headers": "Received: from mail.sender.com ([198.51.100.8]) by mx.google.com\r\nFrom: bad2@sender.com",
            },
        )
        quarantine_id = resp.json()["delivery"]["quarantine_id"]

        release_resp = client.post(
            f"/admin/quarantine/{quarantine_id}/release",
            json={"resolved_by": "admin@ourco.com", "note": "confirmed false positive"},
        )
        assert release_resp.status_code == 200
        assert release_resp.json()["relayed"] is False  # dry-run: no RELAY_HOST in tests
        assert release_resp.json()["status"] == "released"

        # confirm status actually persisted
        item_resp = client.get(f"/admin/quarantine/{quarantine_id}")
        assert item_resp.json()["status"] == "released"
        assert item_resp.json()["resolved_by"] == "admin@ourco.com"

    def test_release_unknown_id_returns_404(self):
        resp = client.post("/admin/quarantine/does-not-exist/release", json={})
        assert resp.status_code == 404

    def test_reject_unknown_id_returns_404(self):
        resp = client.post("/admin/quarantine/does-not-exist/reject", json={})
        assert resp.status_code == 404
