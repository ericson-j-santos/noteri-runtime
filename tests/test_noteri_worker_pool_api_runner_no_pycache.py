"""Real Python import baseline for the immutable Noteri Worker Pool API runner.

No host runtime, task scheduler, HTTP service or real credentials are used.
The fixture constructs a complete staged manifest and a dummy private token in
a temporary directory. This test must fail until the API runner prevents .pyc.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import noteri_worker_pool_api_runner as runner
import noteri_worker_pool_native_stage as stage


class APIRunnerCacheTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.local = Path(temp.name)
        self.root = self.local / "ReqSys" / "NoteriWorkerPool"
        profile = self.local / "ReqSys" / "TodoGlobal24x7" / "host-profile.json"
        profile.parent.mkdir(parents=True)
        profile.write_text('{"profile":"NORMAL"}', encoding="utf-8")

        self.release = self.root / "releases" / runner.SOURCE_SHA
        source_files = {
            "requirements.txt": b"somepackage==1.0\n",
            "app/__init__.py": b"",
            "app/main.py": b"VALUE=1\n",
            "contracts/v1/contract.json": b'{"version":"v1"}',
            "app/secure_file.py": (
                b"import os\n"
                b"def open_private_read(path): return os.open(path, os.O_RDONLY)\n"
                b"def validate_private_fd(fd): assert os.fstat(fd).st_size > 0\n"
                b"def path_matches_fd(fd, path, private): return private and os.fstat(fd).st_size > 0\n"
            ),
        }
        hashes = {}
        for name, payload in source_files.items():
            dest = self.release / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(payload)
            hashes[name] = hashlib.sha256(payload).hexdigest()
        manifest = {
            "schema_version": "1", "kind": "noteri_worker_pool_stage_only",
            "source_sha": runner.SOURCE_SHA, "source_repo": stage.EXPECTED_REPO,
            "activated": False, "files": hashes,
        }
        (self.release / "manifest.json").write_text(json.dumps(manifest), "utf-8")
        self.executable = self.root / "venvs" / runner.SOURCE_SHA / "Scripts" / "python.exe"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b"fake-python-executable-for-test")
        venv_receipt = {
            "source_sha": runner.SOURCE_SHA,
            "requirements_sha256": hashes["requirements.txt"],
            "python_sha256": hashlib.sha256(self.executable.read_bytes()).hexdigest(),
        }
        (self.executable.parents[1] / "noteri-venv-manifest.json").write_text(
            json.dumps(venv_receipt), "utf-8"
        )
        token = self.root / "credentials" / "api-token.txt"
        token.parent.mkdir(parents=True)
        token.write_text("test-only-fake-token", "utf-8")

    def test_valid_runner_import_never_mutates_immutable_staged_release(self):
        with patch.object(sys, "dont_write_bytecode", False):
            release, token = runner.validate(
                root=self.root, executable=self.executable,
                hostname="Noteri", platform="nt",
            )
            self.assertEqual(release, self.release)
            self.assertTrue(token.is_file())
            self.assertFalse(sys.dont_write_bytecode,
                             "original Python bytecode setting must be restored")
        self.assertEqual(list(self.release.rglob("*.pyc")), [],
                         "API runner mutated the immutable staged release")
        manifest = json.loads((self.release / "manifest.json").read_text("utf-8"))
        self.assertTrue(stage.validate_staged(self.release, manifest))

    def test_other_host_denied_before_any_import(self):
        with patch.object(sys, "dont_write_bytecode", False):
            with self.assertRaisesRegex(RuntimeError, "blocked_host"):
                runner.validate(root=self.root, executable=self.executable,
                                hostname="Other", platform="nt")
        self.assertEqual(list(self.release.rglob("*.pyc")), [])

    def test_source_sha_remains_pinned_during_import_fix(self):
        self.assertEqual(runner.SOURCE_SHA, "21fd68dec6f0da92b3e7da201463401ac5429d64")
        self.assertEqual(runner.RULES_SHA, "4e6091a133f8d7d157abe6f83c31ca597812e0a4")


if __name__ == "__main__":
    unittest.main()
