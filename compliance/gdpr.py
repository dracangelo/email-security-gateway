"""
GDPR / CCPA Data Subject Rights Engine.
Supports Subject Access Requests (DSAR data exports) and Right-to-be-Forgotten (Erasure) workflows.
Enforces legal hold checks to block unlawful deletion during active litigation.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from compliance.retention import LegalHoldManager
from security.redact import redact


class LegalHoldConflictError(Exception):
    """Raised when a data erasure request targets an identity covered by an active Legal Hold."""
    pass


class DataSubjectRequestManager:
    """Handles GDPR/CCPA data export and data subject erasure operations."""

    def __init__(self, legal_hold_manager: LegalHoldManager):
        self.legal_hold_manager = legal_hold_manager

    def export_subject_data(
        self,
        email_address: str,
        quarantine_store: Any = None,
        raw_mail_dir: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Export all data associated with a data subject across system repositories."""
        target_email = email_address.lower().strip()
        export_records = {
            "subject_email": target_email,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "quarantine_records": [],
            "raw_mail_files": [],
            "audit_log_entries": [],
        }

        # 1. Quarantine items
        if quarantine_store and hasattr(quarantine_store, "list_all"):
            for item in quarantine_store.list_all():
                sender = getattr(item, "sender", "").lower()
                recipient = getattr(item, "recipient", "").lower()
                if target_email in (sender, recipient):
                    export_records["quarantine_records"].append(
                        item.as_dict() if hasattr(item, "as_dict") else item.__dict__
                    )

        # 2. Raw mail files
        if raw_mail_dir and os.path.exists(raw_mail_dir):
            for root, _, files in os.walk(raw_mail_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if target_email in content.lower():
                                export_records["raw_mail_files"].append(file)
                    except Exception:
                        pass

        # 3. Audit log entries
        if audit_log_path and os.path.exists(audit_log_path):
            with open(audit_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if target_email in line.lower():
                        try:
                            export_records["audit_log_entries"].append(json.loads(line))
                        except Exception:
                            pass

        return export_records

    def erase_subject_data(
        self,
        email_address: str,
        operator: str,
        reason: str,
        quarantine_store: Any = None,
        raw_mail_dir: Optional[str] = None,
        audit_log_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Completely erase or anonymize data subject records across all repositories."""
        target_email = email_address.lower().strip()

        # Enforce Legal Hold check
        if self.legal_hold_manager.is_held(email_address=target_email):
            raise LegalHoldConflictError(
                f"Cannot erase data for subject '{target_email}': active Legal Hold in effect."
            )

        erased_quarantine_count = 0
        erased_raw_mail_count = 0
        anonymized_audit_log_count = 0

        # 1. Erase quarantine store items
        if quarantine_store and hasattr(quarantine_store, "list_all"):
            items = quarantine_store.list_all()
            for item in items:
                sender = getattr(item, "sender", "").lower()
                recipient = getattr(item, "recipient", "").lower()
                q_id = getattr(item, "quarantine_id", "")
                if target_email in (sender, recipient):
                    if hasattr(quarantine_store, "delete"):
                        quarantine_store.delete(q_id)
                        erased_quarantine_count += 1

        # 2. Erase raw mail files
        if raw_mail_dir and os.path.exists(raw_mail_dir):
            for root, _, files in os.walk(raw_mail_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        if target_email in content.lower():
                            os.remove(file_path)
                            erased_raw_mail_count += 1
                    except Exception:
                        pass

        # 3. Anonymize audit log entries
        if audit_log_path and os.path.exists(audit_log_path):
            retained_lines = []
            with open(audit_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if target_email in line.lower():
                        anonymized_line = line.replace(target_email, "[ANONYMIZED_DATA_SUBJECT]")
                        retained_lines.append(anonymized_line)
                        anonymized_audit_log_count += 1
                    else:
                        retained_lines.append(line)

            with open(audit_log_path, "w", encoding="utf-8") as f:
                f.writelines(retained_lines)

        # Generate cryptographic deletion proof
        proof_payload = f"{target_email}:{operator}:{datetime.now(timezone.utc).isoformat()}"
        proof_hash = hashlib.sha256(proof_payload.encode("utf-8")).hexdigest()

        return {
            "subject_email": target_email,
            "erasure_timestamp": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "reason": reason,
            "erased_quarantine_items": erased_quarantine_count,
            "erased_raw_mail_files": erased_raw_mail_count,
            "anonymized_audit_logs": anonymized_audit_log_count,
            "erasure_proof_sha256": proof_hash,
        }
