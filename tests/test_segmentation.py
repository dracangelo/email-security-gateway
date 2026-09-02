import pytest
from fastapi.testclient import TestClient
from webhook_receiver.segmentation import create_admin_app, create_inbound_app


def test_inbound_app_segmentation():
    app = create_inbound_app()
    client = TestClient(app)

    # Health check works on inbound app
    res = client.get("/healthz")
    assert res.status_code == 200

    # Admin endpoints return 404 Not Found on inbound app
    res = client.get("/admin/quarantine")
    assert res.status_code == 404

    res = client.get("/admin/tenants")
    assert res.status_code == 404


def test_admin_app_segmentation():
    app = create_admin_app()
    client = TestClient(app)

    # Health check works on admin app
    res = client.get("/healthz")
    assert res.status_code == 200

    # Admin endpoints return 401 (unauthorized) or 200, but NOT 404 (route exists!)
    res = client.get("/admin/quarantine")
    assert res.status_code in (401, 403, 200)

    # Public webhooks return 404 Not Found on admin app
    res = client.post("/webhooks/sendgrid/inbound/test-secret")
    assert res.status_code == 404

    res = client.post("/webhooks/mailgun/inbound")
    assert res.status_code == 404
