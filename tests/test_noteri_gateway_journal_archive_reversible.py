"""Synthetic Windows proof of isolated archive, exclusive lock, replay, rollback."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import noteri_gateway_journal_archive_reversible as archive
import noteri_gateway_journal_windows_metadata_readonly as meta
from test_noteri_gateway_journal_windows_metadata_readonly import (
    MetadataAuditTests, FakeMetadata, digest,
)


class ArchiveReversibleTests(unittest.TestCase):
    def setUp(self):
        fixture = MetadataAuditTests(
            methodName="test_full_synthetic_audit_is_repeatable_and_never_mutates",
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.fixture = fixture
        fixture.journal["source_commit"] = (
            "58dcd4200f412a866278027ba9e433439a03f3b3"
        )
        fixture.receipt["source_commit"] = (
            "11e2e86d0283e83247d8058d05bbabe3dd7cc2c2"
        )
        (self.root / "update-transaction.json").write_text(
            json.dumps(fixture.journal), encoding="utf-8",
        )
        (self.root / "update-receipt.json").write_text(
            json.dumps(fixture.receipt), encoding="utf-8",
        )
        for name, path in [
            ("JOURNAL_HASH", self.root / "update-transaction.json"),
            ("RECEIPT_HASH", self.root / "update-receipt.json"),
        ]:
            patcher = mock.patch.object(meta, name, digest(path))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.move = lambda src, dst: src.rename(dst)
        self.archive_path = (
            fixture.backups[0] /
            ("recovered-update-transaction-" + "a" * 32 + ".json")
        )

    def test_check_only_replays_without_any_mutation(self):
        first = archive.recover(self.root, helper_loader=FakeMetadata)
        second = archive.recover(self.root, helper_loader=FakeMetadata)
        self.assertEqual(first, second)
        self.assertEqual(first["result"], "JOURNAL_ARCHIVE_PREPARED_READONLY")
        self.assertFalse(first["mutation_performed"])
        self.assertFalse(first["apply_authorized"])
        self.assertTrue((self.root / "update-transaction.json").exists())
        self.assertFalse(self.archive_path.exists())

    def test_move_and_second_execution_are_idempotent(self):
        old = digest(self.root / "update-transaction.json")
        first = archive.recover(self.root, apply=True, mover=self.move,
                                helper_loader=FakeMetadata)
        self.assertEqual(first["result"], "JOURNAL_ARCHIVED_VERIFIED")
        self.assertTrue(first["mutation_performed"])
        self.assertFalse((self.root / "update-transaction.json").exists())
        self.assertEqual(digest(self.archive_path), old)
        replay = archive.recover(self.root, apply=True, mover=self.move,
                                 helper_loader=FakeMetadata)
        self.assertEqual(replay["result"], "JOURNAL_ALREADY_ARCHIVED_VERIFIED")
        self.assertFalse(replay["mutation_performed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(digest(self.archive_path), old)

    def test_failed_post_move_readback_rolls_back_the_original_journal(self):
        original = digest(self.root / "update-transaction.json")
        actual = archive.verify_locked

        def fail_after_move(root, *, archived, helper):
            if archived:
                raise archive.RecoveryBlocked("SYNTHETIC_READBACK_DENIAL")
            return actual(root, archived=archived, helper=helper)

        with mock.patch.object(archive, "verify_locked", side_effect=fail_after_move):
            with self.assertRaisesRegex(archive.RecoveryBlocked,
                                        "POST_MOVE_FAILED_ROLLED_BACK"):
                archive.recover(self.root, apply=True, mover=self.move,
                                helper_loader=FakeMetadata)
        self.assertEqual(digest(self.root / "update-transaction.json"), original)
        self.assertFalse(self.archive_path.exists())

    def test_move_reports_error_after_moving_and_still_rolls_back(self):
        original = digest(self.root / "update-transaction.json")
        def move_then_raise(source, dest):
            source.rename(dest)
            if dest == self.archive_path:
                raise OSError("simulated Win32 ambiguous return")
        with self.assertRaisesRegex(archive.RecoveryBlocked,
                                    "POST_MOVE_FAILED_ROLLED_BACK"):
            archive.recover(self.root, apply=True, mover=move_then_raise,
                            helper_loader=FakeMetadata)
        self.assertEqual(digest(self.root / "update-transaction.json"), original)
        self.assertFalse(self.archive_path.exists())

    def test_collision_while_replaying_does_not_touch_any_file(self):
        archive.recover(self.root, apply=True, mover=self.move,
                        helper_loader=FakeMetadata)
        (self.root / "update-transaction.json").write_bytes(b"unexpected")
        with self.assertRaises((archive.RecoveryBlocked, meta.safe.Blocked)):
            archive.recover(self.root, apply=True, mover=self.move,
                            helper_loader=FakeMetadata)
        self.assertTrue(self.archive_path.exists())

    def test_destination_collision_blocks_before_any_move(self):
        self.archive_path.write_bytes(b"do-not-overwrite")
        original = digest(self.root / "update-transaction.json")
        with self.assertRaisesRegex(archive.RecoveryBlocked,
                                    "JOURNAL_AND_ARCHIVE_CONFLICT"):
            archive.recover(self.root, apply=True, mover=self.move,
                            helper_loader=FakeMetadata)
        self.assertEqual(digest(self.root / "update-transaction.json"), original)
        self.assertEqual(self.archive_path.read_bytes(), b"do-not-overwrite")

    def test_wrong_journal_digest_blocks_before_move(self):
        (self.root / "update-transaction.json").write_text(
            '{"version":1,"transaction_id":"incorrect"}', encoding="utf-8",
        )
        with self.assertRaises((archive.RecoveryBlocked, meta.safe.Blocked)):
            archive.recover(self.root, apply=True, mover=self.move,
                            helper_loader=FakeMetadata)
        self.assertFalse(self.archive_path.exists())

    def test_competing_exclusive_lock_blocks_before_move(self):
        with meta.existing_exclusive_update_lock(self.root):
            with self.assertRaises(meta.Blocked):
                archive.recover(self.root, apply=True, mover=self.move,
                                helper_loader=FakeMetadata)
        self.assertTrue((self.root / "update-transaction.json").exists())
        self.assertFalse(self.archive_path.exists())

    def test_unexpected_archive_only_without_original_or_archive_blocks(self):
        (self.root / "update-transaction.json").unlink()
        with self.assertRaises(archive.RecoveryBlocked):
            archive.recover(self.root, apply=False, mover=self.move,
                            helper_loader=FakeMetadata)


if __name__ == "__main__":
    unittest.main()
