"""
Data Retention Policy & Automated Purge Engine with Legal Hold protection.
Enforces compliance retention periods for quarantine items, raw MIME logs, and audit logs,
while honoring active Legal Holds for items under investigation or litigation.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class RetentionPolicy:
    """Configurable data retention limits (in days)."""
    quarantine_retention_days: int = 30
    raw_mail_retention_days: int = 14
    audit_log_retention_days: int = 90


@dataclass
class LegalHoldRecord:
    hold_id: str
    target_type: str  # "message_id" | "email" | "tenant" | "quarantine_id"
    target_value: str
    reason: str
    created_at: str
    created_by: str


class LegalHoldManager:
    """Manages active legal holds preventing automated data purge."""

    def __init__(self, persistence_file: Optional[str] = None):
        self.persistence_file = persistence_file
        self.holds: Dict[str, LegalHoldRecord] = {}
        if persistence_file and os.path.exists(persistence_file):
            self._load()

    def add_hold(self, target_type: str, target_value: str, reason: str, created_by: str) -> LegalHoldRecord:
        import uuid
        hold_id = f"hold_{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        record = LegalHoldRecord(
            hold_id=hold_id,
            target_type=target_type,
            target_value=target_value.lower().strip(),
            reason=reason,
            created_at=now_iso,
            created_by=created_by,
        )
        self.holds[hold_id] = record
        self._save()
        return record

    def remove_hold(self, hold_id: str) -> bool:
        if hold_id in self.holds:
            del self.holds[hold_id]
            self._save()
            return True
        return False

    def is_held(
        self,
        message_id: Optional[str] = None,
        email_address: Optional[str] = None,
        tenant_id: Optional[str] = None,
        quarantine_id: Optional[str] = None,
    ) -> bool:
        """Check if an artifact is covered by any active legal hold."""
        for hold in self.holds.values():
            val = hold.target_value
            if hold.target_type == "message_id" and message_id and message_id.lower() == val:
                return True
            if hold.target_type == "email" and email_address and email_address.lower() == val:
                return True
            if hold.target_type == "tenant" and tenant_id and tenant_id.lower() == val:
                return True
            if hold.target_type == "quarantine_id" and quarantine_id and quarantine_id.lower() == val:
                return True
        return False

    def list_holds() -> List[LegalHoldRecord]:
        return list(self.holds.values())

    def _save(self) -> None:
        if not self.persistence_file:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.persistence_file)), exist_ok=True)
        data = {h_id: h.__dict__ for h_id, h in self.holds.items()}
        with open(self.persistence_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _load(self) -> None:
        try:
            with open(self.persistence_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for h_id, h_dict in data.items():
                    self.holds[h_id] = LegalHoldRecord(**h_dict)
        except Exception:
            pass


@dataclass
class PurgeSummary:
    quarantine_items_purged: int = 0
    quarantine_items_held: int = 0
    raw_mail_files_purged: int = 0
    raw_mail_files_held: int = 0
    audit_logs_purged: int = 0
    audit_logs_held: int = 0


class DataPurgeEngine:
    """Executes automated retention purges against storage repositories while enforcing legal holds."""

    def __init__(self, legal_hold_manager: LegalHoldManager, policy: Optional[RetentionPolicy] = None):
        self.legal_hold_manager = legal_hold_manager
        self.policy = policy or RetentionPolicy()

    def purge_quarantine_store(self, quarantine_store: Any) -> int:
        """Purge expired quarantine store items."""
        purged_count = 0
        now = time.time()
        max_age_sec = self.policy.quarantine_retention_days * 86400

        items = quarantine_store.list_all() if hasattr(quarantine_store, "list_all") else []
        for item in items:
            created_at = getattr(item, "timestamp", 0) or getattr(item, "created_at", 0)
            if isinstance(created_at, str):
                try:
                    dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    created_at = dt.timestamp()
                except Exception:
                    created_at = now

            if (now - created_at) > max_age_sec:
                msg_id = getattr(item, "message_id", "")
                q_id = getattr(item, "quarantine_id", "")
                tenant_id = getattr(item, "tenant_id", "")
                sender = getattr(item, "sender", "")
                recipient = getattr(item, "recipient", "")

                if not self.legal_hold_manager.is_held(
                    message_id=msg_id, email_address=sender, tenant_id=tenant_id, quarantine_id=q_id
                ) and not self.legal_hold_manager.is_held(email_address=recipient):
                    if hasattr(quarantine_store, "delete"):
                        quarantine_store.delete(q_id)
                        purged_count += 1
        return purged_count

    def purge_raw_mail_directory(self, directory_path: str) -> int:
        """Purge raw MIME files older than retention policy limit."""
        if not os.path.exists(directory_path):
            return 0
        purged_count = 0
        now = time.time()
        max_age_sec = self.policy.raw_mail_retention_days * 86400

        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                mtime = os.path.getmtime(file_path)
                if (now - mtime) > max_age_sec:
                    # Check filename for message ID or hold target
                    if not self.legal_hold_manager.is_held(message_id=file):
                        try:
                            os.remove(file_path)
                            purged_count += 1
                        except OSError:
                            pass
        return purged_count

    def purge_audit_log_file(self, audit_log_path: str) -> int:
        """Purge audit log JSONL records older than retention policy limit."""
        if not os.path.exists(audit_log_path):
            return 0
        now = time.time()
        max_age_sec = self.policy.audit_log_retention_days * 86400

        retained_lines = []
        purged_count = 0

        with open(audit_log_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    ts_str = record.get("timestamp", "")
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    record_age = now - dt.timestamp()
                    msg_id = record.get("message_id")
                    operator = record.get("operator")

                    if record_age > max_age_sec and not self.legal_hold_manager.is_held(message_id=msg_id, email_address=operator):
                        purged_count += 1
                    else:
                        retained_lines.append(line)
                except Exception:
                    retained_lines.append(line)

        with open(audit_log_path, "w", encoding="utf-8") as f:
            f.writelines(retained_lines)

        return purged_count

    def run_full_purge(
        self, quarantine_store: Any = None, raw_mail_dir: Optional[str] = None, audit_log_path: Optional[str] = None
    ) -> PurgeSummary:
        summary = PurgeSummary()
        if quarantine_store:
            summary.quarantine_items_purged = self.purge_quarantine_store(quarantine_store)
        if raw_mail_dir:
            summary.raw_mail_files_purged = self.purge_raw_mail_directory(raw_mail_dir)
        if audit_log_path:
            summary.audit_logs_purged = self.purge_audit_log_file(audit_log_path)
        return summary
