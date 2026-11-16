"""Positive, negative, replay and rollback tests for Unicode worktree recovery.

All filesystem mutation is in unittest temporary directories, never in a real
Noteri worktree. Fake exclusive controller is TEST-ONLY, not deployment proof.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_unicode_empty_directory_recovery as m


class TestOnlyController:
    def __init__(self, *, fencing=True, wrong=False):
        self.fencing = fencing
        self.wrong = wrong
        self.calls = []

    @contextmanager
    def exclusive_claim(self, *, target, expected_head, idempotency_key,
                        correlation_id):
        self.calls.append((target, expected_head, idempotency_key, correlation_id))
        yield SimpleNamespace(
            fencing_proven=self.fencing,
            target="wrong" if self.wrong else target,
            source_head=expected_head,
        )


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / m.TARGETS.__iter__().__next__()
        self.root.mkdir()
        self.target = self.root.name
        self.source = self.root / "an-invalid-name"
        self.source.mkdir()
        self.quarantine = Path(temp.name) / "controlled-quarantine"
        self.controller = TestOnlyController()
        self.call = dict(
            root=self.root, target=self.target, quarantine=self.quarantine,
            authority=self.controller,
            correlation_id="rules213-unicode-safe-test-20261115",
            idempotency_key="rules213-unicode-safe-test-key-20261115",
        )

    def fake_probe(self, root, *, expect_warning):
        self.assertEqual(root, self.root)
        if expect_warning:
            if not self.source.exists():
                raise AssertionError("Missing precondition")
            return self.source, b"warning: redacted"
        if self.source.exists():
            raise m.Blocked("GIT_WARNING_PERSISTS")
        return None, b""

    def test_missing_authority_refuses_before_mutation(self):
        with self.assertRaisesRegex(m.Blocked, "AUTHORITY_NOT_INSTALLED"):
            m.recover_with_authority(**{**self.call, "authority": None})
        self.assertTrue(self.source.exists())
        self.assertFalse(self.quarantine.exists())

    def test_fencing_and_identity_are_not_optional(self):
        for controller in (TestOnlyController(fencing=False),
                           TestOnlyController(wrong=True)):
            with self.subTest(controller=controller):
                with self.assertRaises(m.Blocked):
                    m.recover_with_authority(**{
                        **self.call, "authority": controller,
                    })
                self.assertTrue(self.source.exists())

    def test_unknown_target_and_identifier_fail_closed(self):
        with self.assertRaisesRegex(m.Blocked, "TARGET_DENIED"):
            m.recover_with_authority(**{**self.call, "target": "other-worktree"})
        with self.assertRaisesRegex(m.Blocked, "REQUEST_ID_INVALID"):
            m.recover_with_authority(**{**self.call, "idempotency_key": "../"})
        self.assertFalse(self.controller.calls)

    def test_reversible_quarantine_and_idempotent_replay(self):
        def git(_root, *args):
            return SimpleNamespace(returncode=0, stderr=b"", stdout=b"")
        with patch.object(m, "_validate_root"), patch.object(m, "_git", side_effect=git), patch.object(m, "_probe", side_effect=self.fake_probe):
            moved = m.recover_with_authority(**self.call)
            self.assertEqual(moved["result"], "QUARANTINED_REVERSIBLY")
            self.assertTrue(moved["rollback_available"])
            self.assertFalse(self.source.exists())
            destination = m._destination(self.quarantine, self.target)
            self.assertTrue(destination.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            replayed = m.recover_with_authority(**self.call)
            self.assertEqual(replayed["result"], "ALREADY_QUARANTINED")
            self.assertFalse(replayed["state_changed"])
            self.assertEqual(len(self.controller.calls), 2)

    def test_postmove_failure_rolls_back_exact_original_name(self):
        with patch.object(m, "_validate_root"), patch.object(
            m, "_git", return_value=SimpleNamespace(
                returncode=0, stderr=b"", stdout=b"",
            )
        ), patch.object(m, "_probe", side_effect=[
            (self.source, b"warning: classified"),
            m.Blocked("GIT_WARNING_PERSISTS"),
        ]):
            with self.assertRaisesRegex(m.Blocked, "GIT_WARNING_PERSISTS"):
                m.recover_with_authority(**self.call)
        self.assertTrue(self.source.is_dir())
        self.assertFalse(m._destination(self.quarantine, self.target).exists())

    def test_nonempty_entry_blocks_before_move(self):
        (self.source / "unexpected-data").write_text("preserve", encoding="utf-8")
        with patch.object(m, "_validate_root"), patch.object(
            m, "_git", return_value=SimpleNamespace(
                returncode=0, stderr=b"", stdout=b"",
            )
        ), patch.object(m, "_probe", return_value=(self.source, b"warning")):
            with self.assertRaisesRegex(m.Blocked, "SOURCE_NOT_EMPTY_OR_CHANGED"):
                m.recover_with_authority(**self.call)
        # The temporary data remains in its original directory (rollback);
        # recovery must never delete unknown files.
        self.assertTrue((self.source / "unexpected-data").is_file())

    def test_bad_warning_identity_is_rejected(self):
        with self.assertRaisesRegex(m.Blocked, "WARNING_IDENTITY_MISMATCH"):
            m._warning_identity(
                b"warning: could not open directory 'private/': No such file"
            )

    def test_quarantine_within_target_denied(self):
        with self.assertRaisesRegex(m.Blocked, "QUARANTINE_LOCATION_DENIED"):
            m._safe_quarantine(self.root, self.root / "anything")

    def test_typed_request_is_bounded_but_never_self_authorizing(self):
        request = {
            "schema_version": "noteri-capability-request/v1",
            "capability": m.CAPABILITY,
            "target_host": "Noteri",
            "environment": "DEV",
            "source_sha": "a" * 40,
            "correlation_id": "rules213-unicode-typed-20261116",
            "idempotency_key": "rules213-unicode-idempotent-20261116",
            "confirmation": m.CONFIRM,
            "params": {
                "target": self.target,
                "original_head": m.EXPECTED_HEAD,
                "warning_name_sha256": m.NAME_SHA256,
            },
        }
        data = m.admit_typed_request(
            request, controller_source_sha="a" * 40
        )
        self.assertFalse(data["apply_authorized"])
        self.assertFalse(data["exclusive_lease_proven"])
        self.assertEqual(data["target"], self.target)
        with self.assertRaisesRegex(m.Blocked, "AUTHORITY_NOT_INSTALLED"):
            m.recover_typed_request(
                request, controller_source_sha="a" * 40,
                trusted_quarantine=self.quarantine, authority=None,
            )
        self.assertTrue(self.source.exists())
        for change in (
            {"target_host": "wrong"},
            {"environment": "PROD"},
            {"source_sha": "b" * 40},
            {"confirmation": "invalid"},
            {"params": {**request["params"], "unknown": True}},
            {"params": {**request["params"], "target": "other"}},
            {"params": {**request["params"], "original_head": "b" * 40}},
            {"params": {**request["params"], "warning_name_sha256": "0" * 64}},
        ):
            with self.subTest(change=change):
                with self.assertRaises(m.Blocked):
                    m.admit_typed_request(
                        {**request, **change},
                        controller_source_sha="a" * 40,
                    )

    def test_binary_git_executable_is_not_shell(self):
        with patch.object(m.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stderr=b"", stdout=b"",
        )) as executed:
            m._git(self.root, "rev-parse", "HEAD")
        self.assertFalse(executed.call_args.kwargs["shell"])
        self.assertEqual(executed.call_args.args[0],
                         ("git", "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
