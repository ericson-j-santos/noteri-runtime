"""Sink verifier tests using real temporary files; no task/service calls."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from scripts import noteri_worker_pool_fence_sink as sink

SHA = "a" * 64
NONCE = "b" * 32

class SinkFenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="noteri-sink-")
        self.addCleanup(temp.cleanup)
        self.local = Path(temp.name)
        self.root = self.local.joinpath(*sink.GATEWAY_RELATIVE)
        self.root.mkdir(parents=True)
        self.counter = self.root / "counter.json"
        self.claim = self.root / "active.claim"
        self.env = {
            "LOCALAPPDATA": str(self.local),
            "NOTERI_POOL_MAINTENANCE_FENCE_SEQUENCE": "7",
            "NOTERI_POOL_MAINTENANCE_FENCE_NONCE": NONCE,
            "NOTERI_POOL_MAINTENANCE_SESSION_ID": "noteri-session",
            "NOTERI_POOL_MAINTENANCE_CORRELATION_ID": "noteri:run:7",
            "NOTERI_POOL_MAINTENANCE_SNAPSHOT_SHA256": SHA,
        }
        for patch in (
            mock.patch.object(sink, "_is_noteri", return_value=True),
            mock.patch.object(sink, "_known_localappdata", return_value=self.local),
            mock.patch.object(sink.socket, "gethostname", return_value="noteri"),
            mock.patch.dict(os.environ, self.env),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.counter.write_text(json.dumps(sink._expected_counter(7, "noteri")))
        self.data = {
            "kind": sink.KIND, "target": sink.TARGET, "host": "noteri",
            "pid": os.getppid(), "session_id": "noteri-session",
            "correlation_id": "noteri:run:7", "snapshot_sha256": SHA,
            "nonce": NONCE, "sequence": 7,
        }
        self.write_claim()

    def write_claim(self):
        self.claim.write_text(json.dumps(self.data))

    def rejects(self, pattern=None):
        with self.assertRaises(sink.SinkFenceBlocked) as captured:
            sink.require_active_fence()
        if pattern:
            self.assertIn(pattern, str(captured.exception))

    def test_valid_claim(self):
        self.assertEqual(sink.require_active_fence(), 7)

    def test_missing_environment_fields(self):
        for name in self.env:
            if name == "LOCALAPPDATA":
                continue
            with self.subTest(name=name), mock.patch.dict(os.environ, {name: ""}):
                self.rejects("request_missing")

    def test_host_rejected(self):
        with mock.patch.object(sink, "_is_noteri", return_value=False):
            self.rejects("wrong_host")

    def test_pid_rejected(self):
        self.data["pid"] += 1
        self.write_claim()
        self.rejects("claim_not_owned")

    def test_wrong_nonce_rejected(self):
        with mock.patch.dict(os.environ, {"NOTERI_POOL_MAINTENANCE_FENCE_NONCE": "c"*32}):
            self.rejects("claim_not_owned")

    def test_wrong_sequence_rejected(self):
        with mock.patch.dict(os.environ, {"NOTERI_POOL_MAINTENANCE_FENCE_SEQUENCE": "6"}):
            self.rejects("counter_not_current")

    def test_claim_sequence_rejected(self):
        self.data["sequence"] = 8
        self.write_claim()
        self.rejects("claim_not_owned")

    def test_corrupted_counter_hash_rejected(self):
        bad = sink._expected_counter(7, "noteri")
        bad["sha256"] = "0"*64
        self.counter.write_text(json.dumps(bad))
        self.rejects("counter_not_current")

    def test_missing_claim_rejected(self):
        self.claim.unlink()
        self.rejects("unavailable_or_corrupt")

    def test_localappdata_override_rejected(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": "/attacker/root"}):
            self.rejects("localappdata_override")

    def test_duplicate_json_keys_rejected(self):
        self.claim.write_text(self.claim.read_text()[:-1] + ',"nonce":"attack"}')
        self.rejects("duplicate_json_key")

    def test_symlink_claim_rejected(self):
        other = self.local / "copy.json"
        other.write_text(self.claim.read_text())
        self.claim.unlink()
        try:
            self.claim.symlink_to(other)
        except OSError:
            self.skipTest("symlink unsupported")
        self.rejects("redirected_state_path")

    def test_file_swap_during_read_rejected_even_if_same_size(self):
        # POSIX allows renaming an open file. Windows intentionally denies it,
        # so simulate the same post-read file identity change in os.stat.
        # In both cases, the sink must reject the original descriptor as stale.
        from contextlib import contextmanager
        from types import SimpleNamespace
        original_fdopen = os.fdopen
        original_stat = os.stat
        original = self.counter.read_text()
        read_finished = [False]

        @contextmanager
        def fdopen_with_swap(fd, *args, **kwargs):
            with original_fdopen(fd, *args, **kwargs) as handle:
                class Reader:
                    def read(_, size=-1):
                        data = handle.read(size)
                        read_finished[0] = True
                        if os.name != "nt":
                            self.counter.rename(self.local / "old-counter.json")
                            self.counter.write_text(original)
                        return data
                yield Reader()

        def stat_with_windows_replacement(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if (os.name == "nt" and read_finished[0]
                and Path(path) == self.counter
                and kwargs.get("follow_symlinks") is False):
                return SimpleNamespace(st_dev=result.st_dev,
                                       st_ino=result.st_ino + 1)
            return result

        with mock.patch.object(sink.os, "fdopen", side_effect=fdopen_with_swap):
            with mock.patch.object(sink.os, "stat",
                                   side_effect=stat_with_windows_replacement):
                self.rejects("state_replaced_during_read")
        self.assertTrue(read_finished[0])
        self.assertEqual(self.counter.read_text(), original)

    def test_parent_swap_after_file_entry_read_rejected(self):
        # Swap ancestor immediately after descriptor closure, which occurs
        # after the leaf entry has passed its post-read identity check.
        original_close = os.close
        called = []
        def close_with_parent_swap(fd):
            original_close(fd)
            called.append("closed")
            data = self.counter.read_text()
            self.root.rename(self.local / "old-state-dir")
            self.root.mkdir()
            self.counter.write_text(data)
        with mock.patch.object(sink.os, "close", side_effect=close_with_parent_swap):
            self.rejects("parent_or_entry_replaced")
        self.assertEqual(called, ["closed"])

    def test_large_file_rejected(self):
        self.counter.write_text(" "*(sink.MAX_READ + 1))
        self.rejects("unsafe_state_file")

    def test_boolean_counter_rejected(self):
        bad = sink._expected_counter(7, "noteri")
        bad["sequence"] = True
        self.counter.write_text(json.dumps(bad))
        self.rejects("counter_not_current")

if __name__ == "__main__":
    unittest.main()
