"""Risk1 planning and reversible move tests; no real host release touched."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import noteri_worker_pool_native_stage as stage
from scripts.noteri_worker_pool_release_audit_readonly import OLD_SHA, audit_one
from scripts.noteri_worker_pool_bytecode_quarantine import (
    Blocked, assess, quarantine,
)


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.releases = Path(self.tmp.name)
        self.release = self.releases / OLD_SHA
        values = {p: b"source:" + p.encode() for p in stage.REQUIRED}
        manifest = {
            "schema_version": "1", "kind": "noteri_worker_pool_stage_only",
            "source_sha": OLD_SHA, "source_repo": stage.EXPECTED_REPO,
            "activated": False, "files": {},
        }
        for path, data in values.items():
            f = self.release / path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
            manifest["files"][path] = hashlib.sha256(data).hexdigest()
        # Real release has 38 entries; use 34 additional declared source files.
        for i in range(34):
            name = f"app/fixture_{i:02d}.py"
            file = self.release / name
            file.write_bytes(f"# fixture {i}\n".encode())
            manifest["files"][name] = hashlib.sha256(file.read_bytes()).hexdigest()
        manifest["files"]["app/secure_file.py"] = hashlib.sha256(b"secure\n").hexdigest()
        (self.release / "app" / "secure_file.py").write_bytes(b"secure\n")
        (self.release / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.cache = self.release / "app" / "__pycache__" / "secure_file.cpython-314.pyc"
        self.cache.parent.mkdir()
        self.cache.write_bytes(b"safe-cache")
        self.fingerprint = hashlib.sha256(b"safe-cache").hexdigest()

    def test_plan_does_not_move_bytes(self):
        p = assess(self.releases)
        self.assertEqual(p["result"], "QUARANTINE_PLAN_READY")
        self.assertFalse(p["state_changed"])
        self.assertTrue(self.cache.is_file())
        self.assertEqual(p["cache_sha256"], self.fingerprint)

    def test_apply_preserves_original_and_passes_readback(self):
        result = quarantine(self.releases)
        self.assertEqual(result["result"], "CACHE_QUARANTINED_WITH_READBACK")
        self.assertEqual(result["cache_sha256"], self.fingerprint)
        self.assertEqual(result["manifest_files_sha256_verified"], 39)
        backup = self.releases / ".quarantine" / OLD_SHA / self.cache.name
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b"safe-cache")
        self.assertFalse(self.cache.exists())
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"], "RELEASE_VERIFIED")

    def test_replay_no_second_move(self):
        quarantine(self.releases)
        observed = quarantine(self.releases)
        self.assertEqual(observed["result"], "ALREADY_QUARANTINED")
        self.assertFalse(observed["state_changed"])

    def test_manifest_tamper_never_moves_cache(self):
        (self.release / "requirements.txt").write_bytes(b"tamper")
        with self.assertRaises(Blocked):
            quarantine(self.releases)
        self.assertTrue(self.cache.exists())

    def test_extra_unrelated_file_blocks(self):
        (self.release / "app" / "unexpected.txt").write_bytes(b"untrusted")
        with self.assertRaises(Blocked):
            quarantine(self.releases)
        self.assertTrue(self.cache.exists())

    def test_quarantine_collision_blocks(self):
        dest = self.releases / ".quarantine" / OLD_SHA / self.cache.name
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"other")
        with self.assertRaises(Blocked):
            quarantine(self.releases)
        self.assertEqual(dest.read_bytes(), b"other")
        self.assertTrue(self.cache.exists())

    def test_nonmatching_bytecode_cache_blocks(self):
        self.cache.unlink()
        self.cache.with_name("evil.cpython-314.pyc").write_bytes(b"bad")
        with self.assertRaises(Blocked):
            quarantine(self.releases)

if __name__ == "__main__":
    unittest.main()
