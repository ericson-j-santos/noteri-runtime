from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_venv as native


def release(root: Path) -> Path:
    target = root / reference.RELEASES_RELATIVE / reference.SOURCE_SHA
    files = {
        "app/__init__.py": b"",
        "app/main.py": b"pass\n",
        "contracts/v1/contract.json": b"{}\n",
        "requirements.txt": b"fastapi==0.137.2\n",
    }
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (target / "manifest.json").write_text(json.dumps({
        "schema_version": "1", "kind": "noteri_worker_pool_stage_only",
        "source_sha": reference.SOURCE_SHA, "source_repo": native.stage.EXPECTED_REPO,
        "activated": False,
        "files": {name: hashlib.sha256(content).hexdigest()
                  for name, content in files.items()},
    }), encoding="utf-8")
    return target


class NativeVenvTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        release(self.root)

    def run_case(self, **changes):
        options = dict(localappdata=self.root, hostname="Noteri", platform="nt",
                       profile="NORMAL", python_version=(3, 14), mode="plan")
        options.update(changes)
        with patch.object(reference, "qualify", return_value={"result": "REFERENCE_PRIVATE_UNREAD"}):
            return native.prepare(**options)

    def test_plan_has_no_effect_and_rejects_study(self):
        result = self.run_case()
        self.assertEqual(result["result"], "VENV_PLAN_READY")
        self.assertFalse(result["state_changed"])
        self.assertFalse(result["activated"])
        self.assertFalse(result["token_bytes_read"])
        self.assertFalse((self.root / native.ROOT_RELATIVE / "venvs").exists())
        self.assertEqual(self.run_case(profile="ESTUDO")["result"], "BLOCKED_HOST_PROFILE")

    def test_prepare_replay_and_version_readback(self):
        def install(root: Path, requirements: Path):
            self.assertTrue(requirements.is_file())
            python = native._python(root)
            python.parent.mkdir(parents=True)
            python.write_bytes(b"fixed-python")

        with patch.object(native, "_installed", return_value={"fastapi": "0.137.2"}):
            result = self.run_case(mode="prepare", confirm=native.CONFIRM, install=install)
            self.assertEqual(result["result"], "VENV_PREPARED")
            self.assertTrue(result["state_changed"])
            replay = self.run_case(mode="prepare", confirm=native.CONFIRM, install=install)
            self.assertEqual(replay["result"], "ALREADY_PREPARED")
            self.assertFalse(replay["state_changed"])

    def test_failed_install_rolls_back_only_new_environment(self):
        def fail(root: Path, _requirements: Path):
            root.mkdir()
            (root / "partial").write_text("partial", encoding="utf-8")
            raise native.Blocked("install_failed")

        result = self.run_case(mode="prepare", confirm=native.CONFIRM, install=fail)
        self.assertEqual(result["result"], "BLOCKED_PREPARE_ROLLED_BACK")
        self.assertFalse((self.root / native.ROOT_RELATIVE / "venvs" / native.SOURCE_SHA).exists())

    def test_tampered_release_and_unconfirmed_prepare_fail_closed(self):
        self.assertEqual(self.run_case(mode="prepare")["result"], "BLOCKED_ACTION")
        path = self.root / reference.RELEASES_RELATIVE / reference.SOURCE_SHA / "app" / "main.py"
        path.write_text("altered\n", encoding="utf-8")
        self.assertEqual(self.run_case()["result"], "BLOCKED_INTEGRITY")

    def test_concurrent_prepare_and_existing_unverified_venv_block(self):
        parent = self.root / native.ROOT_RELATIVE / "venvs"
        parent.mkdir(parents=True)
        lock = parent / ".prepare.lock"
        lock.write_text("busy", encoding="utf-8")
        self.assertEqual(self.run_case(mode="prepare", confirm=native.CONFIRM)["result"],
                         "BLOCKED_CONCURRENT_PREPARE")
        lock.unlink()
        (parent / native.SOURCE_SHA).mkdir()
        self.assertEqual(self.run_case()["result"], "BLOCKED_EXISTING_VENV")


if __name__ == "__main__":
    unittest.main()
