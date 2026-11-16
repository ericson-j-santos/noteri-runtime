"""Negative and idempotence tests for the Gateway update read-only preflight."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_authorized_update_preflight_readonly as m


class ReadonlyPreflightTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "gateway"
        (self.root / "bin").mkdir(parents=True)
        (self.root / "config").mkdir()
        self.gateway = self.root / "bin" / "command_gateway.py"
        self.gateway.write_text("# test gateway\n", encoding="utf-8")
        (self.root / "config" / "policy.json").write_text(
            json.dumps({"rules_version": "1.6.20"}), encoding="utf-8"
        )
        self.receipt = self.root / "update-receipt.json"
        self.receipt.write_text(json.dumps({
            "result": "HOST_UPDATE_OK", "source_commit": "a" * 40,
        }), encoding="utf-8")
        self.root_patch = mock.patch.object(m, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.host_patch = mock.patch.object(m.socket, "gethostname", return_value="Noteri")
        self.host_patch.start()
        self.addCleanup(self.host_patch.stop)

    def test_good_receipt_still_does_not_admit_mutation(self):
        before = self.gateway.read_bytes(), self.receipt.read_bytes()
        first = m.inspect(self.root)
        second = m.inspect(self.root)
        self.assertEqual(first, second)
        self.assertEqual(first["result"], "UPDATE_PREFLIGHT_READONLY")
        self.assertFalse(first["apply_admitted"])
        self.assertFalse(first["mutation_performed"])
        self.assertFalse(first["backup_created"])
        self.assertEqual((self.gateway.read_bytes(), self.receipt.read_bytes()), before)

    def test_pending_journal_blocks_even_if_receipt_is_valid(self):
        (self.root / "update-transaction.json").write_text("not inspected", encoding="utf-8")
        self.assertEqual(m.inspect(self.root)["reason"],
                         "PENDING_UPDATE_TRANSACTION_JOURNAL")

    def test_old_failed_rollback_is_not_admitted(self):
        for value in (True, None):
            with self.subTest(value=value):
                self.receipt.write_text(json.dumps({
                    "result": "HOST_UPDATE_BLOCKED",
                    "source_commit": "a" * 40,
                    "mutation_started": value,
                    "rollback_attempted": True,
                    "rollback_succeeded": False,
                }), encoding="utf-8")
                out = m.inspect(self.root)
                self.assertEqual(out["result"], "UPDATE_PREFLIGHT_BLOCKED")
                self.assertFalse(out["apply_admitted"])
                self.assertEqual(out["reason"],
                                 "PREVIOUS_MUTATION_OR_ROLLBACK_NOT_RECONCILED")

    def test_failed_before_mutation_only_allows_readonly_preflight(self):
        self.receipt.write_text(json.dumps({
            "result": "HOST_UPDATE_BLOCKED",
            "mutation_started": False,
        }), encoding="utf-8")
        out = m.inspect(self.root)
        self.assertEqual(out["result"], "UPDATE_PREFLIGHT_READONLY")
        self.assertFalse(out["apply_admitted"])

    def test_receipt_missing_blocks(self):
        self.receipt.unlink()
        self.assertEqual(m.inspect(self.root)["reason"], "UPDATE_RECEIPT_MISSING")

    def test_duplicate_json_keys_denied(self):
        with self.assertRaisesRegex(m.Blocked, "DUPLICATE_JSON_KEYS"):
            m.strict_object(b'{"result":"x","result":"y"}')

    def test_backup_reference_must_be_confined(self):
        self.assertEqual(m._safe_backup_root("/tmp/unapproved")[0], False)
        self.assertEqual(m._safe_backup_root(None)[0], False)

    def test_wrong_host_blocks_without_mutations(self):
        with mock.patch.object(m.socket, "gethostname", return_value="other"):
            with self.assertRaisesRegex(m.Blocked, "HOST_OR_ROOT_MISMATCH"):
                m.inspect(self.root)


if __name__ == "__main__":
    unittest.main()
