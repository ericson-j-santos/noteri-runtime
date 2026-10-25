from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import validate_noteri_worker_pool_credential_artifact as check

WORKFLOW_SHA = "a" * 40


class CredentialArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "evidence.json"
        self.payload = {
            "schema_version": "1",
            "result": "PRIVATE_REFERENCE_READY",
            "preflight_mode": "provision",
            "source_sha": check.SOURCE_SHA,
            "workflow_sha": WORKFLOW_SHA,
            "run_id": "12345",
            "state_changed": True,
            "private_reference": True,
            "token_bytes_read_by_readback": False,
            "credential_value_exposed": False,
            "activated": False,
        }

    def verify(self) -> dict:
        self.path.write_text(json.dumps(self.payload), encoding="utf-8")
        return check.validate(self.path, WORKFLOW_SHA, "12345")

    def test_new_reference_and_idempotent_existing_receipts(self) -> None:
        self.assertEqual(self.verify()["result"], "CREDENTIAL_READBACK_OK")
        self.payload["preflight_mode"] = "existing"
        self.payload["state_changed"] = False
        self.assertFalse(self.verify()["state_changed"])

    def test_false_success_and_scope_violation_are_rejected(self) -> None:
        for key, value in (
            ("private_reference", False), ("activated", True),
            ("credential_value_exposed", True), ("state_changed", False),
        ):
            original = self.payload[key]
            self.payload[key] = value
            with self.assertRaises(check.CredentialArtifactBlocked):
                self.verify()
            self.payload[key] = original

    def test_wrong_run_and_duplicate_json_key_are_rejected(self) -> None:
        self.path.write_text(json.dumps(self.payload), encoding="utf-8")
        with self.assertRaises(check.CredentialArtifactBlocked):
            check.validate(self.path, WORKFLOW_SHA, "99999")
        self.path.write_text('{"result":"PRIVATE_REFERENCE_READY","result":"PRIVATE_REFERENCE_READY"}', encoding="utf-8")
        with self.assertRaises(check.CredentialArtifactBlocked):
            check.validate(self.path, WORKFLOW_SHA, "12345")


if __name__ == "__main__":
    unittest.main()
