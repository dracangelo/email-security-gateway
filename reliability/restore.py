"""
Tested Restore & Verification Procedure Manager.
Decrypts and restores backups with dry-run integrity verification mode.
"""
from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass
from cryptography.fernet import Fernet


@dataclass
class RestoreResult:
    success: bool
    restored_files_count: int = 0
    restored_bytes: int = 0
    dry_run: bool = False
    error_message: str = ""


class RestoreManager:
    """Manages decryption, verification, and restoration of encrypted backups."""

    def verify_backup_integrity(self, encrypted_file_path: str, fernet_key: str) -> bool:
        """Verifies Fernet decryption and tar file integrity without writing to disk (dry-run)."""
        try:
            fernet = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
            with open(encrypted_file_path, "rb") as f:
                encrypted_data = f.read()

            raw_data = fernet.decrypt(encrypted_data)
            with tarfile.open(fileobj=io.BytesIO(raw_data), mode="r") as tar:
                members = tar.getmembers()
                return len(members) >= 0
        except Exception:
            return False

    def restore_backup(
        self,
        encrypted_file_path: str,
        target_dir: str,
        fernet_key: str,
        dry_run: bool = False,
    ) -> RestoreResult:

        if not self.verify_backup_integrity(encrypted_file_path, fernet_key):
            return RestoreResult(success=False, error_message="Backup integrity verification failed (bad key or corrupt archive)")

        fernet = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        raw_data = fernet.decrypt(encrypted_data)
        tar_buf = io.BytesIO(raw_data)

        with tarfile.open(fileobj=tar_buf, mode="r") as tar:
            members = tar.getmembers()
            total_bytes = sum(m.size for m in members)

            if dry_run:
                return RestoreResult(
                    success=True,
                    restored_files_count=len(members),
                    restored_bytes=total_bytes,
                    dry_run=True,
                )

            os.makedirs(target_dir, exist_ok=True)
            tar.extractall(path=target_dir)

            return RestoreResult(
                success=True,
                restored_files_count=len(members),
                restored_bytes=total_bytes,
                dry_run=False,
            )
