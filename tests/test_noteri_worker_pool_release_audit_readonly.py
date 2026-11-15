"""Read-only release audit: missing, malicious, drift and intact cases."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from noteri_worker_pool_release_audit_readonly import OLD_SHA, audit_one, stage


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.releases = Path(self.temp.name)

    def valid(self):
        release = self.releases / OLD_SHA
        payloads = {name: b"content\n" + name.encode()
                    for name in stage.REQUIRED}
        files = {}
        for name, payload in payloads.items():
            file = release / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(payload)
            files[name] = hashlib.sha256(payload).hexdigest()
        manifest = {"schema_version": "1", "kind": "noteri_worker_pool_stage_only",
                    "source_repo": stage.EXPECTED_REPO, "source_sha": OLD_SHA,
                    "activated": False, "files": files}
        (release / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return release, manifest

    def test_absent_is_not_corrupt(self):
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"], "RELEASE_ABSENT")

    def test_manifest_absent_is_distinct(self):
        (self.releases / OLD_SHA).mkdir()
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"], "MANIFEST_ABSENT")

    def test_good_release_hashed_and_revalidated(self):
        _, data = self.valid()
        result = audit_one(self.releases, OLD_SHA)
        self.assertEqual(result["result"], "RELEASE_VERIFIED")
        self.assertEqual(result["files_verified"], len(data["files"]))

    def test_bad_sha_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "RELEASE_SHA_NOT_ALLOWED"):
            audit_one(self.releases, "a"*40)

    def test_identity_mismatch(self):
        directory, data = self.valid()
        data["source_sha"] = "f"*40
        (directory / "manifest.json").write_text(json.dumps(data), "utf-8")
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"],
                         "MANIFEST_IDENTITY_MISMATCH")

    def test_missing_file(self):
        directory, _ = self.valid()
        (directory / "requirements.txt").unlink()
        observed = audit_one(self.releases, OLD_SHA)
        self.assertEqual(observed["result"], "RELEASE_FILES_MISSING_OR_EXTRA")
        self.assertEqual(observed["missing_count"], 1)

    def test_extra_file(self):
        directory, _ = self.valid()
        (directory / "extra.py").write_text("raise ValueError()\n", encoding="utf-8")
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"],
                         "RELEASE_FILES_MISSING_OR_EXTRA")

    def test_tampered_file_bytes(self):
        directory, _ = self.valid()
        (directory / "requirements.txt").write_bytes(b"altered")
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"],
                         "RELEASE_BYTES_MISMATCH")

    def test_bad_file_reference(self):
        directory, data = self.valid()
        data["files"]["../credential.txt"] = "a"*64
        (directory / "manifest.json").write_text(json.dumps(data), "utf-8")
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"],
                         "MANIFEST_FILES_INVALID")

    def test_symlink_denied(self):
        directory, _ = self.valid()
        link = directory / "fake"
        try:
            link.symlink_to(directory / "requirements.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable on this host")
        self.assertEqual(audit_one(self.releases, OLD_SHA)["result"], "BLOCKED_SYMLINK")


if __name__ == "__main__":
    unittest.main()
