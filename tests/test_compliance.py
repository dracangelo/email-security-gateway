import json
import os
import tempfile
import pytest

from compliance.gdpr import DataSubjectRequestManager, LegalHoldConflictError
from compliance.residency import DataResidencyManager, DataResidencyViolationError
from compliance.retention import DataPurgeEngine, LegalHoldManager, RetentionPolicy
from security.redact import redact, redact_dict


class DummyQuarantineItem:
    def __init__(self, q_id, msg_id, sender, recipient, timestamp, tenant_id="tenant_1"):
        self.quarantine_id = q_id
        self.message_id = msg_id
        self.sender = sender
        self.recipient = recipient
        self.timestamp = timestamp
        self.tenant_id = tenant_id

    def as_dict(self):
        return {
            "quarantine_id": self.quarantine_id,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "timestamp": self.timestamp,
            "tenant_id": self.tenant_id,
        }


class DummyQuarantineStore:
    def __init__(self):
        self.items = {}

    def add(self, item):
        self.items[item.quarantine_id] = item

    def list_all(self):
        return list(self.items.values())

    def delete(self, q_id):
        if q_id in self.items:
            del self.items[q_id]


def test_extended_pii_redaction():
    text = "User SSN is 123-45-6789 and Card is 4532012345678901 with IBAN GB33BUKB20201555555555 and Phone 1-800-555-0199"
    redacted = redact(text)
    assert "123-45-6789" not in redacted
    assert "[REDACTED_SSN]" in redacted
    assert "4532012345678901" not in redacted
    assert "[REDACTED_CC]" in redacted
    assert "GB33BUKB20201555555555" not in redacted
    assert "[REDACTED_IBAN]" in redacted
    assert "[REDACTED_PHONE]" in redacted

    d = {"user_ssn": "123-45-6789", "bio": "Call me at 555-555-1234"}
    redacted_d = redact_dict(d)
    assert redacted_d["user_ssn"] == "[REDACTED]"
    assert "[REDACTED_PHONE]" in redacted_d["bio"]


def test_legal_hold_manager():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        mgr = LegalHoldManager(persistence_file=tmp_path)
        hold = mgr.add_hold(target_type="email", target_value="suspect@example.com", reason="Litigation", created_by="admin")
        assert mgr.is_held(email_address="suspect@example.com")
        assert not mgr.is_held(email_address="other@example.com")

        # Reload from disk
        mgr2 = LegalHoldManager(persistence_file=tmp_path)
        assert mgr2.is_held(email_address="suspect@example.com")

        mgr2.remove_hold(hold.hold_id)
        assert not mgr2.is_held(email_address="suspect@example.com")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_data_purge_engine():
    store = DummyQuarantineStore()
    old_ts = 1000.0  # Unix timestamp way in past
    store.add(DummyQuarantineItem("q1", "msg1", "sender@old.com", "recip@old.com", old_ts))
    store.add(DummyQuarantineItem("q2", "msg2", "held@old.com", "recip@old.com", old_ts))

    hold_mgr = LegalHoldManager()
    hold_mgr.add_hold("email", "held@old.com", "Investigation", "secops")

    engine = DataPurgeEngine(legal_hold_manager=hold_mgr, policy=RetentionPolicy(quarantine_retention_days=1))
    summary = engine.run_full_purge(quarantine_store=store)

    assert summary.quarantine_items_purged == 1
    assert "q1" not in store.items
    assert "q2" in store.items


def test_gdpr_dsar_export_and_erasure():
    store = DummyQuarantineStore()
    store.add(DummyQuarantineItem("q10", "msg10", "target@example.com", "victim@example.com", 1000.0))

    hold_mgr = LegalHoldManager()
    dsar_mgr = DataSubjectRequestManager(legal_hold_manager=hold_mgr)

    # 1. Export DSAR
    export_data = dsar_mgr.export_subject_data("target@example.com", quarantine_store=store)
    assert export_data["subject_email"] == "target@example.com"
    assert len(export_data["quarantine_records"]) == 1

    # 2. Legal hold conflict check
    hold_mgr.add_hold("email", "target@example.com", "Subpoena", "legal")
    with pytest.raises(LegalHoldConflictError):
        dsar_mgr.erase_subject_data("target@example.com", "operator1", "GDPR Art 17 Request", quarantine_store=store)

    # Remove hold & erase
    hold_mgr.holds.clear()
    erasure_summary = dsar_mgr.erase_subject_data(
        "target@example.com", "operator1", "GDPR Art 17 Request", quarantine_store=store
    )
    assert erasure_summary["erased_quarantine_items"] == 1
    assert "erasure_proof_sha256" in erasure_summary
    assert "q10" not in store.items


def test_data_residency_manager():
    res_mgr = DataResidencyManager(default_region="us-east-1")
    res_mgr.set_tenant_policy("tenant_eu", primary_region="eu-west-1", allowed_regions=["eu-west-1", "eu-central-1"])

    assert res_mgr.validate_storage_location("tenant_eu", "eu-west-1")
    assert res_mgr.validate_storage_location("tenant_eu", "eu-central-1")
    assert not res_mgr.validate_storage_location("tenant_eu", "us-east-1")

    with pytest.raises(DataResidencyViolationError):
        res_mgr.enforce_residency("tenant_eu", "us-east-1")
