"""Window control tests with synthetic observations, not SQL/Actions certification."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("window", ROOT/"scripts/noteri_qualification_window.py")
window = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(window)
SHA = "a" * 40
CORRELATION = "noteri-window-unit-control"

class WindowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.profile = self.root / "profile.json"
        self.journal = self.root / "journal.json"
        self.write({"host": "Noteri", "profile": "ESTUDO", "accepts_new_development": False})
        self.transitions = []
        self.reads = 0
        self.observations = 0

    def write(self, value):
        self.profile.write_text(json.dumps(value), encoding="utf-8")

    def read(self):
        self.reads += 1
        return json.loads(self.profile.read_text(encoding="utf-8"))

    def set_value(self, profile, correlation):
        self.transitions.append(profile)
        self.write({"host": "Noteri", "profile": profile, "correlation_id": correlation,
                    "accepts_new_development": profile == "NORMAL"})

    def observe(self):
        self.observations += 1
        return {"status": "observed", "host": "Noteri", "source_sha": SHA,
                "correlation_id": CORRELATION, "generated_at": str(self.observations),
                "operating_profile": {"profile": self.read()["profile"],
                                      "source": "file", "verified": True},
                "sql": {"sql_connection_tested": False}, "hml_verified": False,
                "production_touched": False, "secrets_read": False}

    def save(self, value):
        self.journal.write_text(json.dumps(value), encoding="utf-8")

    def load(self):
        return json.loads(self.journal.read_text()) if self.journal.exists() else None

    def run_window(self, **overrides):
        args = dict(source_sha=SHA, correlation_id=CORRELATION, confirmation=window.CONFIRM,
                    read_profile=self.read, set_profile=self.set_value,
                    collect=self.observe, negative_control=lambda: True,
                    read_journal=self.load, write_journal=self.save)
        args.update(overrides)
        return window.run_window(**args)

    def test_positive_window_and_independent_final_read(self):
        result = self.run_window()
        self.assertTrue(result["qualified"])
        self.assertTrue(result["restoration_verified"])
        self.assertEqual(["NORMAL", "ESTUDO"], self.transitions)
        self.assertEqual("ESTUDO", self.read()["profile"])
        self.assertEqual(2, self.observations)
        self.assertFalse(result["actions_qualified"])
        self.assertFalse(result["hml_verified"])
        self.assertEqual(result, self.load())

    def test_negative_control_failure_restores(self):
        result = self.run_window(negative_control=lambda: False)
        self.assertFalse(result["qualified"])
        self.assertEqual("negative_control_failed", result["code"])
        self.assertTrue(result["restoration_verified"])
        self.assertEqual("ESTUDO", self.read()["profile"])

    def test_collector_failure_restores_without_raw_error(self):
        def fail():
            raise RuntimeError("PRIVATE-ERROR-NOT-TO-EMIT")
        result = self.run_window(collect=fail)
        self.assertEqual("RuntimeError", result["code"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual("ESTUDO", self.read()["profile"])

    def test_interrupt_still_restores(self):
        def fail():
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_window(collect=fail)
        self.assertEqual("ESTUDO", self.read()["profile"])
        self.assertTrue(self.load()["restoration_verified"])

    def test_confirmation_precedes_any_read(self):
        with self.assertRaisesRegex(window.Blocked, "confirmation_required"):
            self.run_window(confirmation="NO")
        self.assertEqual(0, self.reads)
        self.assertEqual([], self.transitions)

    def test_bad_sha_precedes_any_read(self):
        with self.assertRaisesRegex(window.Blocked, "source_sha_invalid"):
            self.run_window(source_sha="main")
        self.assertEqual(0, self.reads)

    def test_bad_correlation_precedes_any_read(self):
        with self.assertRaisesRegex(window.Blocked, "correlation_invalid"):
            self.run_window(correlation_id="x" * 128)
        self.assertEqual(0, self.reads)

    def test_wrong_host_does_not_write(self):
        self.write({"host": "Desktop", "profile": "ESTUDO", "accepts_new_development": False})
        with self.assertRaisesRegex(window.Blocked, "profile_host"):
            self.run_window()
        self.assertEqual([], self.transitions)

    def test_initial_normal_not_owned_does_not_write(self):
        self.set_value("NORMAL", "somebody-else")
        self.transitions.clear()
        with self.assertRaisesRegex(window.Blocked, "initial_profile_not_estudo"):
            self.run_window()
        self.assertEqual([], self.transitions)

    def test_malformed_profile_does_not_write(self):
        self.write({"host": "Noteri", "profile": "UNKNOWN"})
        with self.assertRaisesRegex(window.Blocked, "profile_invalid"):
            self.run_window()

    def test_missing_accepts_false_does_not_write(self):
        self.write({"host": "Noteri", "profile": "ESTUDO"})
        with self.assertRaisesRegex(window.Blocked, "initial_profile_not_estudo"):
            self.run_window()

    def test_observation_sha_drift_fails_and_restores(self):
        def changed():
            value = self.observe()
            value["source_sha"] = "b" * 40
            return value
        result = self.run_window(collect=changed)
        self.assertEqual("observation_binding", result["code"])
        self.assertTrue(result["restoration_verified"])

    def test_two_reads_detect_inventory_drift(self):
        def changed():
            value = self.observe()
            value["sql"]["revision"] = self.observations
            return value
        result = self.run_window(collect=changed)
        self.assertEqual("independent_readback_changed", result["code"])
        self.assertTrue(result["restoration_verified"])

    def test_unverified_profile_never_passes(self):
        def changed():
            value = self.observe()
            value["operating_profile"]["verified"] = False
            return value
        result = self.run_window(collect=changed)
        self.assertEqual("normal_observation_unverified", result["code"])

    def test_unreconciled_runtime_blocks_and_restores(self):
        def changed():
            value = self.observe()
            value["rollback"] = {"state_verified": False}
            return value
        result = self.run_window(collect=changed)
        self.assertEqual("runtime_state_unreconciled", result["code"])
        self.assertTrue(result["restoration_verified"])

    def test_durable_intent_failure_blocks_before_normal(self):
        def fail(value):
            raise OSError("storage")
        with self.assertRaises(OSError):
            self.run_window(write_journal=fail)
        self.assertEqual([], self.transitions)

    def test_write_error_after_open_restores(self):
        count = 0
        def fail_second(value):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("storage")
            self.save(value)
        result = self.run_window(write_journal=fail_second)
        self.assertFalse(result["qualified"])
        self.assertEqual("ESTUDO", self.read()["profile"])

    def test_restore_failure_preserves_pending_and_never_succeeds(self):
        def fail_restore(value, correlation):
            if value == "ESTUDO":
                raise OSError("storage")
            self.set_value(value, correlation)
        result = self.run_window(set_profile=fail_restore)
        self.assertEqual("restore_pending", result["state"])
        self.assertFalse(result["qualified"])
        self.assertFalse(result["restoration_verified"])

    def test_replay_never_reopens_window(self):
        first = self.run_window()
        result = self.run_window()
        self.assertTrue(result["replayed"])
        self.assertFalse(result["window_opened_by_this_call"])
        self.assertEqual(["NORMAL", "ESTUDO"], self.transitions)
        self.assertEqual(2, self.observations)

    def test_replay_sha_drift_blocks(self):
        self.run_window()
        with self.assertRaisesRegex(window.Blocked, "replay_sha_conflict"):
            self.run_window(source_sha="b" * 40)

    def test_pending_recovery_only_restores_without_new_work(self):
        self.save({"host": "Noteri", "source_sha": SHA,
                   "correlation_id": CORRELATION, "state": "restore_pending"})
        self.set_value("NORMAL", CORRELATION)
        self.transitions.clear()
        result = self.run_window()
        self.assertEqual("restored_after_interruption", result["state"])
        self.assertEqual(["ESTUDO"], self.transitions)
        self.assertEqual(0, self.observations)
        self.assertFalse(result["qualified"])

    def test_pending_recovery_preserves_other_owner(self):
        self.save({"host": "Noteri", "correlation_id": CORRELATION, "state": "restore_pending"})
        self.set_value("NORMAL", "other-owner")
        self.transitions.clear()
        with self.assertRaisesRegex(window.Blocked, "recovery_owner_conflict"):
            self.run_window()
        self.assertEqual([], self.transitions)

    def test_unknown_journal_state_blocks(self):
        self.save({"host": "Noteri", "state": "unknown"})
        with self.assertRaisesRegex(window.Blocked, "journal_state_invalid"):
            self.run_window()

    def test_concurrent_profile_change_is_not_overwritten(self):
        def changed():
            value = self.observe()
            if self.observations == 2:
                self.set_value("NORMAL", "other-owner")
            return value
        result = self.run_window(collect=changed)
        self.assertFalse(result["restoration_verified"])
        self.assertEqual("restore_owner_conflict", result["restoration_code"])
        self.assertEqual("other-owner", self.read()["correlation_id"])

    def test_lock_rejects_concurrent_window_and_releases(self):
        lock = self.root / "window.lock"
        with window.host_lock(lock):
            with self.assertRaises(OSError):
                with window.host_lock(lock):
                    self.fail("second lock admitted")
        with window.host_lock(lock):
            pass

if __name__ == "__main__":
    unittest.main()
