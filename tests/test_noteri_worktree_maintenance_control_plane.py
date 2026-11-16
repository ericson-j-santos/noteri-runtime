"""End-to-end, negative and tamper tests of maintenance pre-admission.

Fake data never constitutes a live Worker Pool lease or deployment proof.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_worktree_maintenance_control_plane as m
import noteri_unicode_empty_directory_recovery as recovery


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "gateway"
        self.state.mkdir()
        self.target = m.TARGETS[0]
        self.args = dict(
            target=self.target, state_root=self.state,
            source_head="a" * 40, profile="NORMAL",
            host="Noteri",
            owner_rows=[{"name": "python.exe", "pid": 9184}],
            pool_health={
                "result": "WORKER_POOL_API_HEALTHY",
                "http_status": 200, "service": "codex-worker-pool",
                "auth_configured": True,
                "authority_id_present": False,
                "fenced_cutover_enabled": False,
                "storage_backend": "sqlite",
            },
        )

    def _admit(self, *, changes=None, reservation=None, preview=None):
        values = {**self.args, **(changes or {})}
        receipt = reservation if reservation is not None else {
            "state": "RESERVATION_ATTESTED_READONLY",
            "checks": {"identity": True, "snapshot": True},
        }
        source = preview if preview is not None else {
            "result": "RECOVERY_PREFLIGHT_ONLY",
            "empty_directory": True,
        }
        with patch.object(m.diag, "reservation_attestation", return_value=receipt), \
             patch.object(m.recovery, "preview", return_value=source):
            return m.admission(**values)

    def test_actual_pool_profile_below_fence_is_not_authorized(self):
        report = self._admit()
        self.assertTrue(report["pool_healthy"])
        self.assertTrue(report["legacy_session_reservation_valid"])
        self.assertTrue(report["empty_invalid_unicode_directory"])
        self.assertFalse(report["pool_shared_fencing_present"])
        self.assertFalse(report["exclusive_lease_proven"])
        self.assertFalse(report["apply_authorized"])
        self.assertFalse(report["state_changed"])
        self.assertEqual(report["next_required_capability"],
                         "SHARED_AUTHORITY_AND_LEGACY_SESSION_FENCING")

    def test_even_shared_pool_without_legacy_handoff_cannot_apply(self):
        health = {**self.args["pool_health"],
                  "authority_id_present": True,
                  "fenced_cutover_enabled": True,
                  "storage_backend": "postgres"}
        report = self._admit(changes={"pool_health": health})
        self.assertTrue(report["pool_shared_fencing_present"])
        self.assertFalse(report["legacy_sessions_quiescence_proven"])
        self.assertFalse(report["apply_authorized"])
        self.assertFalse(report["exclusive_lease_proven"])
        self.assertEqual(report["next_required_capability"],
                         "LEGACY_SESSION_QUIESCENCE_AND_FENCED_CLAIM")

    def test_wrong_host_profile_target_or_owners_fail_closed(self):
        for changes, reason in (
            ({"host": "other"}, "WRONG_HOST"),
            ({"profile": "ESTUDO"}, "PROFILE_NOT_NORMAL"),
            ({"target": "arbitrary"}, "TARGET_NOT_ALLOWED"),
            ({"source_head": "bad"}, "SOURCE_HEAD_INVALID"),
            ({"owner_rows": []}, "WORKER_POOL_OWNER_NOT_UNIQUE"),
            ({"owner_rows": [{}, {}]}, "WORKER_POOL_OWNER_NOT_UNIQUE"),
            ({"pool_health": {**self.args["pool_health"],
                             "auth_configured": False}}, "WORKER_POOL_UNTRUSTED"),
            ({"pool_health": {**self.args["pool_health"],
                             "http_status": 503}}, "WORKER_POOL_UNTRUSTED"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(m.AdmissionBlocked, reason):
                    self._admit(changes=changes)

    def test_invalid_reservation_and_unicode_preview_block(self):
        with self.assertRaisesRegex(m.AdmissionBlocked, "LEGACY_RESERVATION_NOT_ATTESTED"):
            self._admit(reservation={
                "state": "RESERVATION_MISMATCH",
                "checks": {"snapshot": False},
            })
        with self.assertRaisesRegex(m.AdmissionBlocked, "LEGACY_RESERVATION_NOT_ATTESTED"):
            self._admit(reservation={
                "state": "RESERVATION_ATTESTED_READONLY",
                "checks": {"snapshot": False},
            })
        with self.assertRaisesRegex(m.AdmissionBlocked, "UNICODE_DIRECTORY_PREVIEW_NOT_ATTESTED"):
            self._admit(preview={
                "result": "RECOVERY_PREFLIGHT_ONLY",
                "empty_directory": False,
            })

    def test_controller_without_quiescence_cannot_call_recovery(self):
        payload = {"nonce": "synthetic"}
        for controller in (
            None,
            SimpleNamespace(installed_source_sha="a" * 40,
                            legacy_sessions_quiesced=False,
                            new_claims_fenced=True,
                            exclusive_claim=lambda **kw: None),
            SimpleNamespace(installed_source_sha="a" * 40,
                            legacy_sessions_quiesced=True,
                            new_claims_fenced=False,
                            exclusive_claim=lambda **kw: None),
            SimpleNamespace(installed_source_sha="b" * 40,
                            legacy_sessions_quiesced=True,
                            new_claims_fenced=True,
                            exclusive_claim=lambda **kw: None),
        ):
            with self.subTest(controller=controller):
                with patch.object(m.recovery, "admit_typed_request",
                                  return_value={"target": self.target}), \
                     patch.object(m.recovery, "recover_typed_request") as called:
                    with self.assertRaisesRegex(
                        m.AdmissionBlocked, "INSTALLED_FENCING_CONTROLLER_REQUIRED"
                    ):
                        m.execute_through_installed_controller(
                            payload, expected_source_sha="a" * 40,
                            installed_controller=controller,
                            quarantine_root=Path(self.tmp.name) / "quarantine",
                        )
                    called.assert_not_called()

    def test_installed_controller_adapter_wires_exact_typed_request(self):
        controller = SimpleNamespace(
            installed_source_sha="a" * 40,
            legacy_sessions_quiesced=True,
            new_claims_fenced=True,
            exclusive_claim=lambda **kw: None,
        )
        source = {"schema_version": "noteri-capability-request/v1"}
        result = {"result": "TEST_ONLY_DISPATCH"}
        with patch.object(m.recovery, "admit_typed_request",
                          return_value={"target": self.target}) as admission, \
             patch.object(m.recovery, "recover_typed_request",
                          return_value=result) as called:
            actual = m.execute_through_installed_controller(
                source, expected_source_sha="a" * 40,
                installed_controller=controller,
                quarantine_root=Path(self.tmp.name) / "quarantine",
            )
        self.assertEqual(actual, result)
        admission.assert_called_once()
        called.assert_called_once()
        self.assertIs(called.call_args.kwargs["authority"], controller)

    def test_cli_cannot_apply_or_accept_arbitrary_path(self):
        code = (Path(__file__).resolve().parents[1] / "scripts" /
                "noteri_worktree_maintenance_control_plane.py").read_text("utf-8")
        self.assertNotIn('add_argument("--apply"', code)
        self.assertNotIn('add_argument("--path"', code)
        self.assertNotIn("subprocess.run(", code)
        self.assertNotIn('method="POST"', code)


if __name__ == "__main__":
    unittest.main()
