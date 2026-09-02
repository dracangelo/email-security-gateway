"""
Unit tests for database-backed quarantine & audit store.
"""
import time
from scalability.db_store import DatabaseQuarantineStore, QuarantineRecord


def test_db_quarantine_store_crud():
    store = DatabaseQuarantineStore(":memory:")
    rec = QuarantineRecord(
        msg_id="msg-101",
        tenant_id="tenant-alpha",
        sender="attacker@phish.com",
        recipient="ceo@company.com",
        subject="Urgent Payment Required",
        verdict="quarantine",
        risk_score=85.0,
        status="pending",
        created_at=time.time(),
        raw_payload='{"text": "payload"}',
    )

    saved_id = store.save_record(rec)
    assert saved_id == "msg-101"

    fetched = store.get_record("msg-101")
    assert fetched is not None
    assert fetched["sender"] == "attacker@phish.com"
    assert fetched["status"] == "pending"

    pending = store.list_pending(tenant_id="tenant-alpha")
    assert len(pending) == 1
    assert pending[0]["msg_id"] == "msg-101"

    search_res = store.search_quarantine(query="phish.com")
    assert len(search_res) == 1

    updated = store.update_status("msg-101", "released")
    assert updated is True
    assert store.get_record("msg-101")["status"] == "released"
