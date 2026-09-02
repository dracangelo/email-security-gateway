"""
Tests for Admin UI & Dashboard Module (Task 9):
- HTML Email preview sanitizer (verifying script/iframe/event-handler stripping)
- Plain-text email escaping
- Dashboard analytics computation & audit log search engine
- FastAPI routes: /dashboard, /admin/ui, /admin/ui/api/analytics, /admin/ui/api/preview, /admin/ui/api/bulk-action
"""
from __future__ import annotations

import asyncio
import pytest
from fastapi.testclient import TestClient

from admin_ui import DashboardAnalyticsEngine, SafeEmailPreviewRenderer
from webhook_receiver.app import app, _quarantine_store


def test_safe_email_preview_sanitizer():
    # Dangerous HTML containing scripts, iframes, onload events, and javascript URLs
    dirty_html = """
    <html>
      <body>
        <h1>Invoice Details</h1>
        <script>alert('malicious_xss')</script>
        <iframe src="http://evil-site.com"></iframe>
        <img src="x" onerror="alert('xss')" />
        <a href="javascript:doSomething()">Click Here</a>
        <p>Please review attached document.</p>
      </body>
    </html>
    """

    clean_html = SafeEmailPreviewRenderer.sanitize_html(dirty_html)

    assert "<script>" not in clean_html
    assert "alert('malicious_xss')" not in clean_html
    assert "<iframe" not in clean_html
    assert "onerror=" not in clean_html
    assert 'href="javascript:' not in clean_html
    assert "Invoice Details" in clean_html
    assert "Please review attached document." in clean_html


def test_render_plain_text():
    raw_text = "Hello <user@company.com> & welcome to Gateway!"
    rendered = SafeEmailPreviewRenderer.render_plain_text(raw_text)

    assert "&lt;user@company.com&gt;" in rendered
    assert "&amp;" in rendered


def test_dashboard_analytics_engine():
    analytics = DashboardAnalyticsEngine(quarantine_store=_quarantine_store)
    metrics = analytics.get_summary_metrics()

    assert "summary" in metrics
    assert "false_positive_rate_pct" in metrics["summary"]
    assert "top_blocked_senders" in metrics
    assert "top_blocked_domains" in metrics

    # Audit Search
    mock_records = [
        {"event_type": "quarantine", "total_score": 85, "sender": "bad@phish.com"},
        {"event_type": "deliver", "total_score": 10, "sender": "good@corp.com"},
    ]

    filtered = analytics.search_audit_records(mock_records, query="phish", min_score=70)
    assert len(filtered) == 1
    assert filtered[0]["sender"] == "bad@phish.com"


def test_admin_ui_fastapi_endpoints():
    client = TestClient(app)

    # 1. GET /dashboard
    resp_dashboard = client.get("/dashboard")
    assert resp_dashboard.status_code == 200
    assert "text/html" in resp_dashboard.headers["content-type"]
    assert "Email Auth Gateway SOC" in resp_dashboard.text

    # 2. GET /admin/ui
    resp_ui = client.get("/admin/ui")
    assert resp_ui.status_code == 200
    assert "text/html" in resp_ui.headers["content-type"]

    # 3. GET /admin/ui/api/analytics
    resp_analytics = client.get("/admin/ui/api/analytics")
    assert resp_analytics.status_code == 200
    data = resp_analytics.json()
    assert "summary" in data

    # 4. Store a quarantine item for preview and bulk action test
    rec = asyncio.run(
        _quarantine_store.store(
            raw_message=b"Subject: Test\r\n\r\nHello World",
            message_id="msg_ui_test",
            envelope_from="test@spammer.com",
            envelope_to=["victim@corp.com"],
            total_score=90,
            action="quarantine",
            reasons=["Spam score high"],
        )
    )

    # 5. GET /admin/ui/api/preview/{id}
    resp_preview = client.get(f"/admin/ui/api/preview/{rec.quarantine_id}")
    assert resp_preview.status_code == 200
    preview_data = resp_preview.json()
    assert "html" in preview_data

    # 6. POST /admin/ui/api/bulk-action
    resp_bulk = client.post(
        "/admin/ui/api/bulk-action",
        json={"action": "release", "quarantine_ids": [rec.quarantine_id], "note": "Verified FP"},
    )
    assert resp_bulk.status_code == 200
    bulk_data = resp_bulk.json()
    assert bulk_data["status"] == "success"
    assert bulk_data["processed_count"] == 1
