from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import noteri_worker_pool_control_package as control


class ControlPackageTests(unittest.TestCase):
    def test_pin_matches_version_and_wheel_hash(self):
        source = Path(control.__file__).with_name("noteri_worker_pool_control_requirements.txt")
        self.assertEqual(source.read_text(encoding="utf-8").strip(), control.REQUIREMENT)
        self.assertEqual(control.TARGET_NAME, "pywin32-312-cp314")

    def test_incomplete_target_fails_closed(self):
        with TemporaryDirectory() as directory:
            self.assertFalse(control.verify(Path(directory)))

    def test_failed_install_removes_only_new_staging(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "control" / control.TARGET_NAME
            with patch.object(control, "qualify", return_value=(root, target)), \
                    patch.object(control.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                result = control.prepare(root, root)
            self.assertEqual(result, "BLOCKED_PREPARE")
            self.assertFalse(target.exists())
            self.assertEqual(list((root / "control").iterdir()), [])

    def test_import_verification_runs_after_target_move(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "control" / control.TARGET_NAME
            def installed(command, **_kwargs):
                Path(command[command.index("--target") + 1]).mkdir()
                return subprocess.CompletedProcess(command, 0)
            def verified(path):
                self.assertEqual(path, target)
                self.assertTrue(target.is_dir())
                return True
            with patch.object(control, "qualify", return_value=(root, target)), \
                    patch.object(control.subprocess, "run", side_effect=installed), \
                    patch.object(control, "verify_files", return_value=True), \
                    patch.object(control, "verify", side_effect=verified):
                self.assertEqual(control.prepare(root, root), "CONTROL_PACKAGE_PREPARED")


if __name__ == "__main__":
    unittest.main()
