from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import noteri_worker_pool_api_uac as uac


class UacLauncherTests(unittest.TestCase):
    def test_arguments_are_fixed(self):
        command = uac.elevated_arguments()
        self.assertIn("scripts.noteri_worker_pool_native_activation", command)
        self.assertIn(uac.activation.CONFIRM, command)
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


if __name__ == "__main__":
    unittest.main()
