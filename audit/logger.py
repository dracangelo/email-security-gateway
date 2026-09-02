"""
Append-only JSONL audit trail: one line per processed message, redacted,
with a content hash for chain-of-custody -- you can prove which exact
message a decision was made about without storing the message a second
time in the log itself.

Single-process-safe via an asyncio.Lock. If you run multiple worker
*processes* against the same file path, individual write() calls are
still small enough to be atomic on typical POSIX filesystems for
same-line appends, but for anything you actually depend on, ship these
lines to a real log aggregator (JSONL is meant to be trivially parseable
by one) rather than trusting concurrent local-file appends across
processes.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from security.redact import redact_dict


class AuditLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def record(
        self,
        message_id: str,
        message_hash: str,
        envelope_from: str,
        action: str,
        total_score: int,
        reasons: list[str],
    ) -> None:
        entry = redact_dict(
            {
                "timestamp": time.time(),
                "message_id": message_id,
                "message_hash": message_hash,
                "envelope_from": envelope_from,
                "action": action,
                "total_score": total_score,
                "reasons": reasons,
            }
        )
        line = json.dumps(entry, sort_keys=True) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append, line)

    async def record_admin_action(
        self,
        operator: str,
        action: str,
        target_id: str,
        note: str = "",
    ) -> None:
        entry = redact_dict(
            {
                "timestamp": time.time(),
                "event_type": "admin_action",
                "operator": operator,
                "action": action,
                "target_id": target_id,
                "note": note,
            }
        )
        line = json.dumps(entry, sort_keys=True) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)

    def read_all(self) -> list[dict]:
        """Convenience for tests/CLI inspection -- not used on the hot path."""
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
