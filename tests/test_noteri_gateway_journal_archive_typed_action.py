"""Typed archive execution admission: positive, denial, replay and exact source."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_journal_archive_typed_action as action


HEAD = "f" * 40


def request() -> dict:
    return {
        "schema_version": 1,
        "action_id": action.ACTION,
        "host": "Noteri",
        "environment": "DEV",
        "source_head": HEAD,
        "journal_sha256": action.JOURNAL,
        "receipt_sha256": action.RECEIPT,
        "backup_manifest_sha256": action.BACKUP,
        "archive_filename": action.EXPECTED_DESTINATION,
        "correlation_id": "noteri-journal-archive-typed-test-20261116",
        "idempotency_key": "noteri-journal-757ec16e-once-20261116",
        "confirm": action.CONFIRM,
        "max_extra_cost_brl": "0.00",
        "rollback_contract": "win32-same-volume-verified-rollback-v1",
    }


def recovered(archived: bool = True) -> dict:
    return {
        "result": "JOURNAL_ARCHIVED_VERIFIED" if archived else
                  "JOURNAL_ARCHIVE_PREPARED_READONLY",
        "archive_name": action.EXPECTED_DESTINATION,
        "journal_sha256": action.JOURNAL,
        "receipt_sha256": action.RECEIPT,
        "mutation_performed": archived,
        "archived": archived,
        "update_lock_held": True,
        "backups_verified": 2,
    }


class ActionGateTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(action.socket, "gethostname", return_value="Noteri")
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(action, "source_sha", return_value=HEAD)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(action.archive, "recover", return_value=recovered())
        self.recovery = p.start()
        self.addCleanup(p.stop)

    def test_exact_action_admitted_once(self):
        result = action.run_typed(request(), apply=True)
        self.assertEqual(result["result"], "JOURNAL_ARCHIVED_VERIFIED")
        self.assertTrue(result["mutation_performed"])
        self.recovery.assert_called_once_with(apply=True)

    def test_check_only_is_not_mutation(self):
        self.recovery.return_value = recovered(archived=False)
        result = action.run_typed(request(), apply=False)
        self.assertFalse(result["mutation_performed"])
        self.recovery.assert_called_once_with(apply=False)

    def test_replay_invokes_same_action_not_new_target(self):
        self.recovery.return_value = {
            **recovered(),
            "result": "JOURNAL_ALREADY_ARCHIVED_VERIFIED",
            "mutation_performed": False, "archived": True,
        }
        result = action.run_typed(request(), apply=True)
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["result"], "JOURNAL_ALREADY_ARCHIVED_VERIFIED")
        self.recovery.assert_called_once_with(apply=True)

    def test_denies_scope_mutations_before_recover(self):
        changes = {
            "action_id": "noteri.gateway.anything",
            "host": "Other",
            "environment": "PROD",
            "journal_sha256": "0" * 64,
            "receipt_sha256": "0" * 64,
            "backup_manifest_sha256": "0" * 64,
            "archive_filename": "unapproved.json",
            "confirm": "execute",
            "max_extra_cost_brl": "0.01",
            "rollback_contract": "skip",
            "source_head": "0" * 40,
            "idempotency_key": "reused",
            "correlation_id": "bad",
        }
        for key, wrong in changes.items():
            with self.subTest(key=key):
                item = request()
                item[key] = wrong
                with self.assertRaises(action.AdmissionBlocked):
                    action.run_typed(item, apply=True)
        self.recovery.assert_not_called()

    def test_denies_unknown_or_missing_key(self):
        for change in ("added", "removed"):
            with self.subTest(change=change):
                item = request()
                if change == "added":
                    item["command"] = "bad"
                else:
                    del item["source_head"]
                with self.assertRaisesRegex(action.AdmissionBlocked, "REQUEST_KEYS_INVALID"):
                    action.run_typed(item, apply=True)
        self.recovery.assert_not_called()

    def test_head_drift_denied(self):
        with mock.patch.object(action, "source_sha", return_value="0" * 40):
            with self.assertRaisesRegex(action.AdmissionBlocked,
                                        "CHECKOUT_HEAD_MISMATCH"):
                action.run_typed(request(), apply=True)
        self.recovery.assert_not_called()

    def test_invalid_host_denied_before_recover(self):
        with mock.patch.object(action.socket, "gethostname", return_value="other"):
            with self.assertRaisesRegex(action.AdmissionBlocked,
                                        "NOTERI_WINDOWS_BYTECODE_POLICY_DENIED"):
                action.run_typed(request(), apply=True)
        self.recovery.assert_not_called()

    def test_unexpected_or_tampered_archive_readback_denied(self):
        self.recovery.return_value = {
            **recovered(), "journal_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(action.AdmissionBlocked,
                                    "ARCHIVE_READBACK_IDENTITY_INVALID"):
            action.run_typed(request(), apply=True)


if __name__ == "__main__":
    unittest.main()
