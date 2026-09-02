"""
Unit tests for tested restore procedure manager.
"""
import os
import tempfile
from reliability.backup import BackupManager
from reliability.restore import RestoreManager


def test_restore_backup():
    backup_mgr = BackupManager()
    restore_mgr = RestoreManager()
    key = backup_mgr.generate_backup_key()

    with tempfile.TemporaryDirectory() as temp_dir:
        src_file = os.path.join(temp_dir, "quarantine.db")
        with open(src_file, "w") as f:
            f.write("Quarantine DB contents line 1\nLine 2\n")

        backup_file = os.path.join(temp_dir, "backup.enc")
        backup_mgr.create_backup(src_file, backup_file, key)

        # 1. Verification (dry-run)
        valid = restore_mgr.verify_backup_integrity(backup_file, key)
        assert valid is True

        dry_res = restore_mgr.restore_backup(backup_file, os.path.join(temp_dir, "dry_restore"), key, dry_run=True)
        assert dry_res.success is True
        assert dry_res.dry_run is True
        assert dry_res.restored_files_count == 1

        # 2. Real Restore
        restore_dir = os.path.join(temp_dir, "restore_target")
        res = restore_mgr.restore_backup(backup_file, restore_dir, key, dry_run=False)
        assert res.success is True
        assert res.dry_run is False
        assert os.path.exists(os.path.join(restore_dir, "quarantine.db"))

        # 3. Bad Key Failure
        bad_res = restore_mgr.restore_backup(backup_file, restore_dir, backup_mgr.generate_backup_key())
        assert bad_res.success is False
