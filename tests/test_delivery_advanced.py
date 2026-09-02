"""
Tests for advanced Delivery & Response Actions features (Task 6):
- Direct mailbox actions (Graph / Gmail API integration)
- Retroactive removal ("Auto-Zap") engine
- End-user "Report Phish" button ingestion
- End-user quarantine digest generator
- Outbound mail protection & DLP scanner
- Delivery receipt confirmation tracking
- FastAPI endpoints (/api/v1/report-phish, /admin/zap, /admin/digest/send)
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from decision_engine.feedback_loop import FeedbackLoopEngine
from delivery import (
    DLPScanner,
    DeliveryTracker,
    DirectMailboxService,
    QuarantineDigestGenerator,
    QuarantineStore,
    RetroactiveZapEngine,
    UserReportHandler,
)
from webhook_receiver.app import app


def test_direct_mailbox_service_fallback():
    service = DirectMailboxService()
    # M365 unconfigured fallback
    res_m365 = pytest.mark.anyio
    import asyncio
    res_junk = asyncio.run(service.move_to_junk("m365", "user@corp.com", "msg123"))
    assert res_junk["status"] == "simulated"

    res_del = asyncio.run(service.delete_message("m365", "user@corp.com", "msg123"))
    assert res_del is True

    # Google fallback
    res_google = asyncio.run(service.move_to_junk("google", "user@domain.com", "msg456"))
    assert res_google["status"] == "simulated"

    with pytest.raises(ValueError):
        asyncio.run(service.move_to_junk("unsupported_provider", "a@b.com", "123"))


def test_retroactive_zap_engine():
    zap_engine = RetroactiveZapEngine()
    zap_engine.register_delivery(
        message_id="msg_001",
        recipients=[("m365", "victim@corp.com", "graph_id_1")],
        urls=["https://phish.example.com/login"],
        attachment_hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )

    import asyncio
    zapped_url = asyncio.run(zap_engine.trigger_zap_by_url("https://phish.example.com/login"))
    assert zapped_url == ["msg_001"]

    stats = zap_engine.get_stats()
    assert stats["zapped_messages"] == 1


def test_user_report_handler():
    feedback = FeedbackLoopEngine()
    zap_engine = RetroactiveZapEngine()
    zap_engine.register_delivery(
        message_id="msg_reported",
        recipients=[("google", "user@domain.com", "gmail_123")],
        urls=["https://bad-link.com/reset"],
    )

    handler = UserReportHandler(feedback_loop=feedback, zap_engine=zap_engine)
    import asyncio
    res = asyncio.run(
        handler.process_report(
            reporter_email="user@domain.com",
            message_id="msg_reported",
            sender="attacker@malicious.com",
            subject="Urgent Security Alert",
            body="Please update account at https://bad-link.com/reset",
        )
    )

    assert res["status"] == "processed"
    assert res["urls_extracted"] == 1
    assert res["zapped_messages_count"] == 1
    assert feedback.get_domain_adjustment("malicious.com") > 0


def test_quarantine_digest_generator(tmp_path):
    store = QuarantineStore(quarantine_dir=str(tmp_path / "quarantine"))
    generator = QuarantineDigestGenerator(quarantine_store=store, secret_key="digest_test_secret")

    token = generator.generate_token("q_100", "user@company.com")
    assert generator.verify_token("q_100", "user@company.com", token) is True
    assert generator.verify_token("q_100", "user@company.com", "bad_token") is False

    # Store a dummy quarantine item
    import asyncio
    asyncio.run(
        store.store(
            raw_message=b"From: bad@sender.com\r\nTo: user@company.com\r\nSubject: Test\r\n\r\nBody",
            message_id="msg_q",
            envelope_from="bad@sender.com",
            envelope_to=["user@company.com"],
            total_score=65,
            action="quarantine",
            reasons=["Spam content"],
        )
    )

    digest = generator.build_digest_for_recipient("user@company.com")
    assert digest["count"] == 1
    assert "user@company.com" in digest["html"]
    assert "Request Release" in digest["html"]


def test_dlp_scanner():
    scanner = DLPScanner(max_outbound_burst_per_10m=3)

    # 1. Test SSN Leak detection
    res_ssn = scanner.inspect_outbound(
        sender="employee@corp.com",
        recipients=["external@partner.com"],
        subject="Employee Info",
        text_body="Here is the SSN: 123-45-6789 for tax forms.",
    )
    assert res_ssn.is_blocked is True
    assert any("SSN Leak" in v for v in res_ssn.policy_violations)

    # 2. Test AWS Key Leak
    res_aws = scanner.inspect_outbound(
        sender="dev@corp.com",
        recipients=["vendor@cloud.com"],
        subject="Config",
        text_body="Access key: AKIAIOSFODNN7EXAMPLE",
    )
    assert res_aws.is_blocked is True
    assert any("AWS Access Key" in v for v in res_aws.policy_violations)

    # 3. Test Compromised Account Burst Detection
    for _ in range(3):
        scanner.inspect_outbound(sender="spammer@corp.com", recipients=["a@b.com"], text_body="Hello")

    res_burst = scanner.inspect_outbound(sender="spammer@corp.com", recipients=["a@b.com"], text_body="Hello")
    assert res_burst.anomalous_volume is True
    assert res_burst.is_blocked is True


def test_delivery_tracker():
    tracker = DeliveryTracker()
    r = tracker.record_receipt("msg_1", "rcpt@test.com", "relayed", dsn_code="2.0.0", detail="250 OK")

    assert r.status == "relayed"
    receipts = tracker.get_receipts_for_message("msg_1")
    assert len(receipts) == 1

    stats = tracker.get_stats()
    assert stats["relayed"] == 1


def test_delivery_advanced_fastapi_routes():
    client = TestClient(app)

    # 1. Report phish endpoint
    resp_report = client.post(
        "/api/v1/report-phish",
        json={
            "reporter_email": "user@corp.com",
            "message_id": "msg_999",
            "sender": "scammer@phish.com",
            "subject": "Wire Transfer",
            "body": "Click http://phish-site.com",
        },
    )
    assert resp_report.status_code == 200
    data = resp_report.json()
    assert data["status"] == "processed"

    # 2. Admin Zap endpoint
    resp_zap = client.post(
        "/admin/zap",
        headers={"Authorization": "Bearer admin_secret"},
        json={"url": "http://phish-site.com", "reason": "Security Alert"},
    )
    assert resp_zap.status_code == 200
    data_zap = resp_zap.json()
    assert data_zap["mode"] == "by_url"

    # 3. Admin Digest Send endpoint
    resp_digest = client.post(
        "/admin/digest/send",
        headers={"Authorization": "Bearer admin_secret"},
        json={"recipient_email": "user@corp.com"},
    )
    assert resp_digest.status_code == 200
