"""Independent synthetic tests for journal/receipt/backup read-only binding."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_journal_binding_readonly as audit


def h(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class JournalBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.patcher = patch.object(audit, "ROOT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.host = patch.object(audit.socket, "gethostname", return_value="Noteri")
        self.host.start()
        self.addCleanup(self.host.stop)
        self.journal_backup = self.root / ("backup-20261116-020000-" + "a" * 32)
        self.receipt_backup = self.root / ("backup-20261116-020100-" + "b" * 32)
        self.managed_desired = b"installed-current"
        self.managed_previous = b"historical-backup"
        for backup in (self.journal_backup, self.receipt_backup):
            (backup / "files").mkdir(parents=True)
            entries = {}
            for relative in sorted(audit.legacy.MANAGED):
                managed = self.root.joinpath(*relative.split("/"))
                managed.parent.mkdir(parents=True, exist_ok=True)
                managed.write_bytes(self.managed_desired)
                saved = backup / "files" / relative
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(self.managed_previous)
                entries[relative] = {
                    "existed": True,
                    "previous_sha256": h(self.managed_previous),
                    "previous_size": len(self.managed_previous),
                    "desired_sha256": h(self.managed_desired),
                    "desired_size": len(self.managed_desired),
                }
            (backup / "rollback-manifest.json").write_text(
                json.dumps({"version": 2, "install_root": str(self.root),
                            "entries": entries}), encoding="utf-8",
            )
        self.journal = {
            "version": 1, "transaction_id": "1" * 32,
            "source_commit": "a" * 40,
            "backup_dir": str(self.journal_backup),
            "prepared_at": "2026-11-16T00:00:00Z",
        }
        self.receipt = {
            "result": "HOST_UPDATE_OK", "transaction_id": "2" * 32,
            "source_commit": "b" * 40,
            "backup_dir": str(self.receipt_backup),
            "mutation_started": True,
        }
        self.write_state()

    def write_state(self):
        (self.root / "update-receipt.json").write_text(
            json.dumps(self.receipt), encoding="utf-8",
        )
        (self.root / "update-transaction.json").write_text(
            json.dumps(self.journal), encoding="utf-8",
        )

    def test_old_journal_mismatches_current_receipt_but_both_backups_intact(self):
        before = [(p, p.read_bytes()) for p in self.root.rglob("*") if p.is_file()]
        result = audit.inspect(self.root)
        self.assertEqual(result["identity_classification"],
                         "JOURNAL_DIFFERS_FROM_CURRENT_SUCCESS_RECEIPT")
        self.assertFalse(result["same_transaction_id"])
        self.assertFalse(result["same_source_commit"])
        self.assertFalse(result["same_backup_directory"])
        self.assertTrue(result["journal_backup_content_complete"])
        self.assertTrue(result["receipt_backup_content_complete"])
        self.assertTrue(result["receipt_current_desired_content_complete"])
        self.assertFalse(result["journal_move_authorized"])
        self.assertFalse(result["state_changed"])
        self.assertEqual(before, [(p, p.read_bytes()) for p in self.root.rglob("*")
                                  if p.is_file()])

    def test_matched_transaction_still_does_not_authorize_recovery(self):
        self.receipt.update({
            "transaction_id": self.journal["transaction_id"],
            "source_commit": self.journal["source_commit"],
            "backup_dir": self.journal["backup_dir"],
        })
        self.write_state()
        result = audit.inspect(self.root)
        self.assertEqual(result["identity_classification"],
                         "JOURNAL_AND_RECEIPT_SAME_TRANSACTION")
        self.assertFalse(result["journal_move_authorized"])
        self.assertFalse(result["windows_security_metadata_verified"])

    def test_tampered_journal_backup_detected(self):
        path = self.journal_backup / "files" / "bin" / "command_gateway.py"
        path.write_bytes(b"tampered")
        result = audit.inspect(self.root)
        self.assertEqual(result["journal_backup"]["backup_content_matches"], 6)
        self.assertFalse(result["journal_backup_content_complete"])
        self.assertFalse(result["journal_move_authorized"])

    def test_tampered_current_installed_file_detected(self):
        (self.root / "bin" / "command_gateway.py").write_bytes(b"tampered")
        result = audit.inspect(self.root)
        self.assertFalse(result["receipt_current_desired_content_complete"])

    def test_duplicate_json_keys_fail_closed(self):
        (self.root / "update-transaction.json").write_bytes(
            b'{"version":1,"version":1}'
        )
        with self.assertRaisesRegex(audit.safe.Blocked, "DUPLICATE_JSON_KEYS"):
            audit.inspect(self.root)

    def test_missing_or_invalid_journal_blocks(self):
        (self.root / "update-transaction.json").unlink()
        with self.assertRaises(audit.safe.Blocked):
            audit.inspect(self.root)
        self.write_state()
        self.journal["transaction_id"] = "wrong"
        self.write_state()
        with self.assertRaisesRegex(audit.Blocked, "JOURNAL_TX_INVALID"):
            audit.inspect(self.root)

    def test_backup_outside_fixed_root_blocked(self):
        self.journal["backup_dir"] = str(self.root.parent / ("backup-20261116-020000-" + "c" * 32))
        self.write_state()
        with self.assertRaisesRegex(audit.Blocked, "BACKUP_REFERENCE_OUTSIDE_INSTALL_ROOT"):
            audit.inspect(self.root)

    def test_backup_manifest_entry_set_wrong_fails_closed(self):
        path = self.journal_backup / "rollback-manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["entries"].pop("bin/command_gateway.py")
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(audit.Blocked, "BACKUP_MANAGED_SET_MISMATCH"):
            audit.inspect(self.root)

    def test_invalid_host_denied(self):
        with patch.object(audit.socket, "gethostname", return_value="unrelated"):
            with self.assertRaisesRegex(audit.Blocked, "HOST_NOTERI_REQUIRED"):
                audit.inspect(self.root)


if __name__ == "__main__":
    unittest.main()
