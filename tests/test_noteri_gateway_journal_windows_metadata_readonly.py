"""Regression tests for the fixed Noteri Win32 journal metadata audit."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_journal_windows_metadata_readonly as audit
import noteri_gateway_journal_binding_readonly as binding


def digest(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


class FakeMetadata:
    def _windows_persisted_file_state(self, path):
        return {"version": 1, "attributes": 0,
                "security": {"owner_sid": "TEST"},
                "streams": []}

    def _validate_windows_persisted_state(self, value, destination):
        if value != self._windows_persisted_file_state(None):
            raise ValueError("invalid expected metadata")

    def _windows_persisted_state_equivalent(self, expected, actual):
        return expected == actual

    def _windows_get_security_descriptor(self, path):
        return b"test-windows-security-descriptor"


class MetadataAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "gateway"
        self.root.mkdir()
        self.backups = [
            self.root / ("backup-20261116-022500-" + "1" * 32),
            self.root / ("backup-20261116-022600-" + "2" * 32),
        ]
        self.expected = FakeMetadata()._windows_persisted_file_state(None)
        for i, backup in enumerate(self.backups):
            (backup / "files").mkdir(parents=True)
            entries = {}
            for rel in sorted(binding.legacy.MANAGED):
                live = self.root.joinpath(*rel.split("/"))
                live.parent.mkdir(parents=True, exist_ok=True)
                live.write_bytes(b"current")
                saved = backup / "files" / rel
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(b"previous")
                # The original historical journal backup must describe a
                # runtime equal to its previous state, while the newer
                # receipt's backup describes the installed desired state.
                prior_content = b"current" if i == 0 else b"previous"
                entries[rel] = {
                    "source": "synthetic",
                    "existed": True,
                    "previous_sha256": hashlib.sha256(prior_content).hexdigest(),
                    "previous_size": len(prior_content),
                    "desired_sha256": hashlib.sha256(b"current").hexdigest(),
                    "desired_size": len(b"current"),
                    "previous_windows_state": self.expected,
                }
                if i == 0:
                    saved.write_bytes(b"current")
            (backup / "rollback-manifest.json").write_text(
                json.dumps({
                    "version": 2,
                    "install_root": str(self.root),
                    "entries": entries,
                }), encoding="utf-8",
            )
        self.journal = {
            "version": 1, "transaction_id": "a" * 32,
            "source_commit": "a" * 40,
            "backup_dir": str(self.backups[0]),
        }
        self.receipt = {
            "result": "HOST_UPDATE_OK", "transaction_id": "b" * 32,
            "source_commit": "b" * 40,
            "backup_dir": str(self.backups[1]),
        }
        (self.root / "update-transaction.json").write_text(
            json.dumps(self.journal), encoding="utf-8"
        )
        (self.root / "update-receipt.json").write_text(
            json.dumps(self.receipt), encoding="utf-8"
        )
        (self.root / "update.lock").write_bytes(b"\0")
        pins = [
            ("JOURNAL_HASH", digest(self.root / "update-transaction.json")),
            ("RECEIPT_HASH", digest(self.root / "update-receipt.json")),
            ("JOURNAL_MANIFEST_HASH", digest(self.backups[0] / "rollback-manifest.json")),
            ("RECEIPT_MANIFEST_HASH", digest(self.backups[1] / "rollback-manifest.json")),
        ]
        for name, value in pins:
            p = mock.patch.object(audit, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(binding, "ROOT", self.root)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(audit, "ROOT", self.root)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(audit.socket, "gethostname", return_value="Noteri")
        p.start()
        self.addCleanup(p.stop)

    def test_full_synthetic_audit_is_repeatable_and_never_mutates(self):
        before = {str(p): digest(p) for p in self.root.rglob("*") if p.is_file()}
        out1 = audit.inspect(self.root, helper_loader=FakeMetadata)
        out2 = audit.inspect(self.root, helper_loader=FakeMetadata)
        self.assertEqual(out1, out2)
        self.assertEqual(out1["result"], "JOURNAL_WINDOWS_METADATA_AUDIT_OK")
        self.assertEqual(out1["rollback_historical"]["backup_security_matches"], 7)
        self.assertEqual(out1["rollback_current"]["backup_security_matches"], 7)
        self.assertFalse(out1["journal_move_authorized"])
        self.assertFalse(out1["mutation_performed"])
        self.assertEqual(before, {
            str(p): digest(p) for p in self.root.rglob("*") if p.is_file()
        })

    def test_persisted_acl_mismatch_fails_closed(self):
        changed = self.backups[0] / "rollback-manifest.json"
        value = json.loads(changed.read_text(encoding="utf-8"))
        value["entries"]["bin/command_gateway.py"]["previous_windows_state"] = {
            "version": 1, "attributes": 1, "security": {}, "streams": [],
        }
        changed.write_text(json.dumps(value), encoding="utf-8")
        with mock.patch.object(audit, "JOURNAL_MANIFEST_HASH", digest(changed)):
            with self.assertRaisesRegex(audit.Blocked, "WINDOWS_FILE_METADATA_UNAVAILABLE"):
                audit.inspect(self.root, helper_loader=FakeMetadata)

    def test_current_receipt_drift_blocks(self):
        (self.root / "update-receipt.json").write_bytes(b"tampered")
        with self.assertRaises(audit.Blocked):
            audit.inspect(self.root, helper_loader=FakeMetadata)

    def test_exclusive_lock_denies_simultaneous_open(self):
        path = self.root / "update.lock"
        before = digest(path)
        with audit.existing_exclusive_update_lock(self.root):
            with self.assertRaisesRegex(audit.Blocked,
                                        "UPDATE_LOCK_BUSY_OR_ACCESS_DENIED"):
                with audit.existing_exclusive_update_lock(self.root):
                    self.fail("must not acquire second lock")
        self.assertEqual(digest(path), before)
        # A new read-only use can acquire it after release.
        with audit.existing_exclusive_update_lock(self.root):
            pass

    def test_missing_lock_is_not_created(self):
        (self.root / "update.lock").unlink()
        with self.assertRaisesRegex(audit.Blocked, "UPDATE_LOCK_MISSING_OR_INVALID"):
            with audit.existing_exclusive_update_lock(self.root):
                pass
        self.assertFalse((self.root / "update.lock").exists())

    def test_unsafe_helper_hash_fails_closed(self):
        with mock.patch.object(audit.safe, "require_regular", return_value=b"wrong"):
            with self.assertRaisesRegex(audit.Blocked,
                                        "PINNED_METADATA_HELPER_HASH_INVALID"):
                audit._fixed_helper()


if __name__ == "__main__":
    unittest.main()
