from __future__ import annotations

import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import noteri_worker_pool_api_uac as uac
from scripts import noteri_worker_pool_api_elevated_entry as entry


class UacLauncherTests(unittest.TestCase):
    def test_arguments_are_fixed(self):
        command = uac.elevated_arguments(Path("C:/private/activation-uac-abc.json"))
        self.assertIn("scripts.noteri_worker_pool_api_elevated_entry", command)
        self.assertIn(uac.activation.CONFIRM, command)
        self.assertIn("activation-uac-abc.json", command)
        self.assertNotIn("api-token", command)

    def test_confirmation_blocks_before_qualifying(self):
        with patch.object(uac.activation, "qualify") as qualify:
            self.assertEqual(uac.launch(confirm="wrong")["result"], "BLOCKED_ACTION")
            qualify.assert_not_called()

    def test_uac_launch_then_readback(self):
        class Shell:
            def ShellExecuteW(self, *args):
                self.args = args
                return 42
        shell = Shell()
        with patch.dict(uac.os.environ, {"LOCALAPPDATA": "C:\\local"}), \
                patch.object(uac.activation, "qualify", return_value=(Path("x"), Path("y"), Path("z"))), \
                patch.object(uac.activation, "is_admin", return_value=False), \
                patch.object(uac.ctypes, "windll", create=True) as windll, \
                patch.object(uac.activation, "existing_task", return_value=(Path("x"), Path("t"), Path("p"), Path("r"))), \
                patch.object(uac.activation, "verify_api", return_value=True):
            windll.shell32 = shell
            result = uac.launch(confirm=uac.CONFIRM)
        self.assertEqual(result["result"], "API_ACTIVE")
        self.assertEqual(shell.args[1], "runas")
        self.assertEqual(shell.args[5], uac.SW_SHOWNORMAL)

    def test_elevated_child_writes_sanitized_failure(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / ("activation-uac-" + "a" * 32 + ".json")
            with patch.dict(entry.os.environ, {"LOCALAPPDATA": directory}), \
                    patch.object(entry.venv, "_paths", return_value=(root, root, root)), \
                    patch.object(entry.activation, "is_admin", return_value=True), \
                    patch.object(entry.activation, "main", side_effect=lambda: print(json.dumps({
                        "result": "BLOCKED_ACTIVATION_ROLLED_BACK", "phase": "register",
                        "activated": False}))):
                result = entry.run(receipt, entry.activation.CONFIRM)
            self.assertEqual(result["phase"], "register")
            self.assertTrue(result["elevation_observed"])
            self.assertEqual(json.loads(receipt.read_text())["result"],
                             "BLOCKED_ACTIVATION_ROLLED_BACK")
            self.assertNotIn("api-token", receipt.read_text())

    def test_launcher_reports_child_failure_without_retry(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            class Id:
                hex = "b" * 32
            receipt = root / ("activation-uac-" + Id.hex + ".json")
            def launched(*_args):
                receipt.write_text(json.dumps({"schema_version": "1",
                                               "source_sha": uac.reference.SOURCE_SHA,
                                               "result": "BLOCKED_ACTIVATION_ROLLED_BACK",
                                               "phase": "register",
                                               "elevation_observed": True}))
                return 42
            with patch.dict(uac.os.environ, {"LOCALAPPDATA": directory}), \
                    patch.object(uac.activation, "qualify", return_value=(root, root, root)), \
                    patch.object(uac.activation, "is_admin", return_value=False), \
                    patch.object(uac.uuid, "uuid4", return_value=Id()), \
                    patch.object(uac.ctypes, "windll", create=True) as windll:
                windll.shell32.ShellExecuteW.side_effect = launched
                result = uac.launch(confirm=uac.CONFIRM)
            self.assertEqual(result["result"], "BLOCKED_UAC_CHILD")
            self.assertEqual(result["child_result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
            self.assertEqual(result["phase"], "register")


if __name__ == "__main__":
    unittest.main()
