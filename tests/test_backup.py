"""
Unit tests for automated encrypted backup & key rotation module.
"""
import os
import tempfile
from reliability.backup import BackupManager


def test_backup_create_and_rotate_key():
    manager = BackupManager()
    key1 = manager.generate_backup_key()
    key2 = manager.generate_backup_key()

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test source file
        src_file = os.path.join(temp_dir, "test_data.txt")
        with open(src_file, "w") as f:
            f.write("Secret quarantine database contents")

        backup_file = os.path.join(temp_dir, "quarantine_backup.enc")
        meta = manager.create_backup(src_file, backup_file, key1, key_id="key-1")

        assert meta.size_bytes > 0
        assert meta.key_id == "key-1"
        assert os.path.exists(backup_file)

        # Rotate key to key2
        new_sha256 = manager.rotate_backup_key(backup_file, key1, key2)
        assert new_sha256 is not None
