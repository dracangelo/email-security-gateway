import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.fernet import Fernet, InvalidToken

from audit.logger import AuditLogger
from security.encryption import RawMailCipher


def _run(coro):
    return asyncio.run(coro)


class TestAuditLogger:
    def test_record_and_read_back(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(log_path))
        _run(logger.record(
            message_id="m1", message_hash="abc123", envelope_from="a@b.com",
            action="quarantine", total_score=95, reasons=["SPF hard fail"],
        ))
        entries = logger.read_all()
        assert len(entries) == 1
        assert entries[0]["action"] == "quarantine"
        assert entries[0]["total_score"] == 95

    def test_multiple_records_appended_in_order(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(log_path))

        async def scenario():
            for i in range(3):
                await logger.record(
                    message_id=f"m{i}", message_hash="h", envelope_from="a@b.com",
                    action="forward", total_score=0, reasons=[],
                )

        _run(scenario())
        entries = logger.read_all()
        assert [e["message_id"] for e in entries] == ["m0", "m1", "m2"]

    def test_secrets_in_reasons_are_redacted(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(log_path))
        _run(logger.record(
            message_id="m1", message_hash="h", envelope_from="a@b.com",
            action="quarantine", total_score=100,
            reasons=["body contained api_key: sk-live-abc123xyz"],
        ))
        entries = logger.read_all()
        assert "sk-live-abc123xyz" not in entries[0]["reasons"][0]

    def test_read_all_on_missing_file_returns_empty(self, tmp_path):
        logger = AuditLogger(str(tmp_path / "does_not_exist.jsonl"))
        assert logger.read_all() == []

    def test_creates_parent_directories(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "audit.jsonl"
        AuditLogger(str(nested))
        assert nested.parent.exists()


class TestRawMailCipher:
    def test_disabled_without_key_passes_through_unchanged(self):
        cipher = RawMailCipher(key="")
        data = b"raw eml bytes"
        assert cipher.enabled() is False
        assert cipher.encrypt(data) == data
        assert cipher.decrypt(data) == data

    def test_round_trip_with_key(self):
        key = Fernet.generate_key().decode()
        cipher = RawMailCipher(key=key)
        assert cipher.enabled() is True
        data = b"raw eml bytes with credentials and PII"
        ciphertext = cipher.encrypt(data)
        assert ciphertext != data
        assert cipher.decrypt(ciphertext) == data

    def test_wrong_key_fails_to_decrypt(self):
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()
        ciphertext = RawMailCipher(key=key_a).encrypt(b"secret data")
        with pytest.raises(InvalidToken):
            RawMailCipher(key=key_b).decrypt(ciphertext)

    def test_tampered_ciphertext_fails_to_decrypt(self):
        key = Fernet.generate_key().decode()
        cipher = RawMailCipher(key=key)
        ciphertext = bytearray(cipher.encrypt(b"secret data"))
        ciphertext[-5] ^= 0xFF  # flip some bits near the end
        with pytest.raises(InvalidToken):
            cipher.decrypt(bytes(ciphertext))
