"""
Tests for Multi-Tenancy Module (Task 7):
- Tenant data model & provisioning workflow
- Per-tenant domain resolution
- Cryptographic & storage directory isolation
- Per-tenant rate limit quota enforcement
- MSP cross-tenant dashboard view
- FastAPI admin CRUD endpoints for tenants
"""
from __future__ import annotations

import asyncio
import os
import pytest
from fastapi.testclient import TestClient

from multi_tenancy import (
    MSPAdminView,
    Tenant,
    TenantIsolatedCipher,
    TenantIsolatedQuarantine,
    TenantManager,
    TenantRateLimiter,
)
from security.rate_limit import RateLimitExceeded
from webhook_receiver.app import app


def test_tenant_manager_lifecycle(tmp_path):
    mgr = TenantManager()

    # 1. Create Tenant
    tenant = mgr.create_tenant(
        tenant_id="tenant_acme",
        name="Acme Corp",
        domains=["acme.com", "acme.org"],
        warn_threshold=45,
        quarantine_threshold=75,
    )
    assert tenant.tenant_id == "tenant_acme"
    assert tenant.status == "active"

    # 2. Domain Resolution
    found_tenant = mgr.get_tenant_by_domain("user@acme.com")
    assert found_tenant is not None
    assert found_tenant.tenant_id == "tenant_acme"

    found_subdomain = mgr.get_tenant_by_domain("sales.acme.org")
    assert found_subdomain is not None
    assert found_subdomain.tenant_id == "tenant_acme"

    assert mgr.get_tenant_by_domain("unknown.com") is None

    # 3. Update Tenant Config
    updated = mgr.update_tenant("tenant_acme", warn_threshold=50, domains=["acme.com", "acme.io"])
    assert updated.warn_threshold == 50
    assert mgr.get_tenant_by_domain("acme.io") is not None
    assert mgr.get_tenant_by_domain("acme.org") is None

    # 4. Offboard Tenant
    dummy_dir = tmp_path / "tenant_acme"
    dummy_dir.mkdir()
    (dummy_dir / "data.txt").write_text("test")

    ok = mgr.deprovision_tenant("tenant_acme", purge_data=True, storage_base_dir=str(tmp_path))
    assert ok is True
    assert mgr.get_tenant("tenant_acme") is None
    assert not dummy_dir.exists()


def test_tenant_cryptographic_isolation(tmp_path):
    mgr = TenantManager()
    t1 = mgr.create_tenant("t1", "Tenant 1", domains=["t1.com"])
    t2 = mgr.create_tenant("t2", "Tenant 2", domains=["t2.com"])

    isolated_q = TenantIsolatedQuarantine(base_quarantine_dir=str(tmp_path / "quarantine"), tenant_manager=mgr)

    # Store message for T1
    rec1 = asyncio.run(
        isolated_q.store(
            tenant_id="t1",
            raw_message=b"From: secret@t1.com\r\nTo: user@t1.com\r\n\r\nConfidential T1 mail",
            message_id="msg_t1",
            envelope_from="secret@t1.com",
            envelope_to=["user@t1.com"],
            total_score=80,
            action="quarantine",
            reasons=["High risk"],
        )
    )
    assert rec1.quarantine_id is not None

    # Verify storage under T1 directory
    t1_dir = tmp_path / "quarantine" / "t1"
    assert t1_dir.exists()
    files = list(t1_dir.glob("*.eml*"))
    assert len(files) == 1

    # Attempt decrypting T1 file with T2 key -> fails
    cipher1 = isolated_q.isolated_cipher.get_cipher_for_tenant(t1)
    cipher2 = isolated_q.isolated_cipher.get_cipher_for_tenant(t2)

    raw_encrypted = files[0].read_bytes()
    decrypted_t1 = cipher1.decrypt(raw_encrypted)
    assert b"Confidential T1 mail" in decrypted_t1

    with pytest.raises(Exception):
        cipher2.decrypt(raw_encrypted)


def test_tenant_rate_limiter():
    limiter = TenantRateLimiter()

    # Allow up to 3 requests
    limiter.check_tenant_rate_limit("t_test", max_requests_per_minute=3)
    limiter.check_tenant_rate_limit("t_test", max_requests_per_minute=3)
    limiter.check_tenant_rate_limit("t_test", max_requests_per_minute=3)

    # 4th request exceeds quota
    with pytest.raises(RateLimitExceeded):
        limiter.check_tenant_rate_limit("t_test", max_requests_per_minute=3)


def test_msp_admin_view(tmp_path):
    mgr = TenantManager()
    mgr.create_tenant("t_alpha", "Alpha Corp", domains=["alpha.com"])
    mgr.create_tenant("t_beta", "Beta Corp", domains=["beta.com"])

    isolated_q = TenantIsolatedQuarantine(base_quarantine_dir=str(tmp_path / "quarantine"), tenant_manager=mgr)
    msp_view = MSPAdminView(tenant_manager=mgr, isolated_quarantine=isolated_q)

    msp_view.record_message_processed("t_alpha")
    msp_view.record_message_processed("t_alpha")
    msp_view.record_message_processed("t_beta")

    summary = msp_view.generate_dashboard_summary()
    assert summary["aggregate_metrics"]["total_tenants"] == 2
    assert summary["aggregate_metrics"]["total_messages_processed"] == 3
    assert len(summary["tenants"]) == 2


def test_multi_tenancy_fastapi_admin_routes():
    client = TestClient(app)

    # 1. Create tenant via API
    resp_create = client.post(
        "/admin/tenants",
        headers={"Authorization": "Bearer admin_secret"},
        json={
            "tenant_id": "api_tenant",
            "name": "API Tenant",
            "domains": ["api-tenant.com"],
            "warn_threshold": 42,
        },
    )
    assert resp_create.status_code == 200
    data = resp_create.json()
    assert data["tenant_id"] == "api_tenant"
    assert data["warn_threshold"] == 42

    # 2. List tenants
    resp_list = client.get("/admin/tenants", headers={"Authorization": "Bearer admin_secret"})
    assert resp_list.status_code == 200
    tenants = resp_list.json()
    assert any(t["tenant_id"] == "api_tenant" for t in tenants)

    # 3. Get single tenant
    resp_get = client.get("/admin/tenants/api_tenant", headers={"Authorization": "Bearer admin_secret"})
    assert resp_get.status_code == 200
    assert resp_get.json()["name"] == "API Tenant"

    # 4. Update tenant
    resp_put = client.put(
        "/admin/tenants/api_tenant",
        headers={"Authorization": "Bearer admin_secret"},
        json={"quarantine_threshold": 80},
    )
    assert resp_put.status_code == 200
    assert resp_put.json()["quarantine_threshold"] == 80

    # 5. MSP Dashboard
    resp_msp = client.get("/admin/msp/dashboard", headers={"Authorization": "Bearer admin_secret"})
    assert resp_msp.status_code == 200
    assert "aggregate_metrics" in resp_msp.json()

    # 6. Delete tenant
    resp_del = client.delete("/admin/tenants/api_tenant", headers={"Authorization": "Bearer admin_secret"})
    assert resp_del.status_code == 200
    assert resp_del.json()["status"] == "deprovisioned"
