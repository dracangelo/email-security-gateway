"""
Quarantine storage. The original design doc's operational rule was
explicit: 'avoid blind dropping -- false positives happen, quarantine
suspicious emails rather than outright deleting them so admins can review
and release legitimate business communications.' This module is that --
raw message (encrypted, same RawMailCipher as the main mail log) plus a
metadata record an admin (or an admin API you build on top of this) can
list, release back to the recipient, or reject.

One JSON metadata file + one message file per quarantined item, on local
disk. Simple, human-inspectable (an admin can literally `cat` the JSON),
and doesn't require standing up a database for this to work. At real
volume, add an index (Redis/Postgres) for list_pending() rather than
globbing the directory -- noted in the README, not solved here.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

from security.encryption import RawMailCipher

from .models import QuarantineRecord


class QuarantineStore:
    def __init__(self, quarantine_dir: str, cipher: RawMailCipher | None = None):
        self.dir = Path(quarantine_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cipher = cipher or RawMailCipher(key="")
        self._lock = asyncio.Lock()

    def _eml_path(self, quarantine_id: str) -> Path:
        suffix = ".eml.enc" if self.cipher.enabled() else ".eml"
        return self.dir / f"{quarantine_id}{suffix}"

    def _meta_path(self, quarantine_id: str) -> Path:
        return self.dir / f"{quarantine_id}.json"

    async def store(
        self,
        raw_message: bytes,
        message_id: str,
        envelope_from: str,
        envelope_to: list[str],
        total_score: int,
        action: str,
        reasons: list[str],
    ) -> QuarantineRecord:
        quarantine_id = str(uuid.uuid4())
        record = QuarantineRecord(
            quarantine_id=quarantine_id,
            message_id=message_id,
            envelope_from=envelope_from,
            envelope_to=envelope_to,
            total_score=total_score,
            action=action,
            reasons=reasons,
            quarantined_at=time.time(),
        )
        payload = self.cipher.encrypt(raw_message)
        async with self._lock:
            await asyncio.to_thread(self._eml_path(quarantine_id).write_bytes, payload)
            await asyncio.to_thread(self._meta_path(quarantine_id).write_text, json.dumps(record.as_dict()))
        return record

    def _load_record(self, quarantine_id: str) -> QuarantineRecord | None:
        path = self._meta_path(quarantine_id)
        if not path.exists():
            return None
        return QuarantineRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def get_raw_message(self, quarantine_id: str) -> bytes | None:
        path = self._eml_path(quarantine_id)
        if not path.exists():
            return None
        return self.cipher.decrypt(path.read_bytes())

    def get_record(self, quarantine_id: str) -> QuarantineRecord | None:
        return self._load_record(quarantine_id)

    def list_pending(self) -> list[QuarantineRecord]:
        records = []
        for meta_file in sorted(self.dir.glob("*.json")):
            try:
                record = QuarantineRecord.from_dict(json.loads(meta_file.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, TypeError):
                continue  # skip a corrupted metadata file rather than failing the whole listing
            if record.status == "pending":
                records.append(record)
        return records

    async def _resolve(self, quarantine_id: str, status: str, resolved_by: str, note: str) -> QuarantineRecord | None:
        async with self._lock:
            record = self._load_record(quarantine_id)
            if record is None:
                return None
            record.status = status
            record.resolved_at = time.time()
            record.resolved_by = resolved_by
            record.resolution_note = note
            await asyncio.to_thread(self._meta_path(quarantine_id).write_text, json.dumps(record.as_dict()))
            return record

    async def release(self, quarantine_id: str, resolved_by: str = "", note: str = "") -> QuarantineRecord | None:
        """Marks the item released. Returns the record (with the raw
        message retrievable via get_raw_message) so the caller can relay
        it -- this module doesn't relay itself, that's delivery.relay's job,
        keeping 'decide to release' separate from 'actually deliver'."""
        return await self._resolve(quarantine_id, "released", resolved_by, note)

    async def reject(self, quarantine_id: str, resolved_by: str = "", note: str = "") -> QuarantineRecord | None:
        return await self._resolve(quarantine_id, "rejected", resolved_by, note)
