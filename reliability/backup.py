"""
Automated Encrypted Backup & Key Rotation Manager.
Creates Fernet-encrypted backup archives of quarantine stores, audit logs, and configuration.
Includes encryption key generation and key rotation procedures.
"""
from __future__ import annotations

import hashlib
import os
import tarfile
import time
import uuid
from dataclasses import dataclass
from cryptography.fernet import Fernet


@dataclass
class BackupMetadata:
    backup_id: str
    timestamp: float
    file_path: str
    size_bytes: int
    sha256_hash: str
    key_id: str


class BackupManager:
    """Manages creation, key rotation, and metadata of encrypted backups."""

    @staticmethod
    def generate_backup_key() -> str:
        return Fernet.generate_key().decode()

    @staticmethod
    def _sha256_file(file_path: str) -> str:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def create_backup(self, source_path: str, output_path: str, fernet_key: str, key_id: str = "default") -> BackupMetadata:
        fernet = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)

        # 1. Package source into unencrypted tar in memory
        tar_bytes_io = os.path.join(os.path.dirname(output_path), f"temp_{uuid.uuid4().hex}.tar")
        with tarfile.open(tar_bytes_io, "w") as tar:
            if os.path.isdir(source_path):
                tar.add(source_path, arcname=os.path.basename(source_path))
            else:
                tar.add(source_path, arcname=os.path.basename(source_path))

        with open(tar_bytes_io, "rb") as f:
            raw_data = f.read()
        os.remove(tar_bytes_io)

        # 2. Encrypt using Fernet
        encrypted_data = fernet.encrypt(raw_data)

        # 3. Write encrypted file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)

        size = os.path.getsize(output_path)
        sha256 = self._sha256_file(output_path)
        backup_id = str(uuid.uuid4())

        return BackupMetadata(
            backup_id=backup_id,
            timestamp=time.time(),
            file_path=output_path,
            size_bytes=size,
            sha256_hash=sha256,
            key_id=key_id,
        )

    def rotate_backup_key(self, encrypted_file_path: str, old_key: str, new_key: str) -> str:
        """Decrypts backup with old_key and re-encrypts with new_key."""
        old_fernet = Fernet(old_key.encode() if isinstance(old_key, str) else old_key)
        new_fernet = Fernet(new_key.encode() if isinstance(new_key, str) else new_key)

        with open(encrypted_file_path, "rb") as f:
            encrypted_data = f.read()

        raw_data = old_fernet.decrypt(encrypted_data)
        reencrypted_data = new_fernet.encrypt(raw_data)

        with open(encrypted_file_path, "wb") as f:
            f.write(reencrypted_data)

        return self._sha256_file(encrypted_file_path)
