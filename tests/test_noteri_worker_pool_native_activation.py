from __future__ import annotations

import getpass
import socket
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import noteri_worker_pool_native_activation as activation


class ActivationTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.root = self.path / "runtime"
        self.root.mkdir()
        self.source = self.path / "scripts"
        self.source.mkdir()
        for name in activation.RUNNER_FILES:
            (self.source / name).write_bytes(name.encode())
        self.venv = self.root / "venvs" / "pinned"
        self.token = self.root / "credentials" / "api-token.txt"
        self.user = f"{socket.gethostname()}\\{getpass.getuser()}"

    def test_xml_requires_limited_s4u_boot_and_exact_action(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        raw = activation.task_xml(python, runner, self.user)
        self.assertTrue(activation.task_matches(raw, python, runner, self.user))
        altered = raw.replace(b"S4U", b"InteractiveToken")
        self.assertFalse(activation.task_matches(altered, python, runner, self.user))
        sid_export = raw.replace(self.user.encode(), b"S-1-5-21-12345")
        with patch.object(activation, "account_sid", return_value="S-1-5-21-12345"):
            self.assertTrue(activation.task_matches(sid_export, python, runner, self.user))
        self.assertIn(b"LeastPrivilege", raw)
        self.assertIn(b"BootTrigger", raw)

    def test_register_readback_and_health_success(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        observed = []
        def scheduled(*args):
            observed.append(args[0])
            raw = activation.task_xml(python, runner, self.user) if args[0] == "/Query" else b""
            return subprocess.CompletedProcess(args, 0, stdout=raw)
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "wait_api", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "API_ACTIVATED")
        self.assertEqual(observed, ["/Create", "/Query", "/Run"])
        self.assertFalse((self.root / "bin" / "registration.xml").exists())
        self.assertTrue((self.root / "data").is_dir())
        self.assertEqual((self.root / "bin" / activation.RUNNER_FILES[0]).read_bytes(),
                         activation.RUNNER_FILES[0].encode())

    def test_registration_failure_rolls_back_new_bin(self):
        observed = []
        def scheduled(*args):
            observed.append(args[0])
            return subprocess.CompletedProcess(args, 1, stdout=b"")
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "task_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "register")
        self.assertEqual(observed, ["/Create", "/Query"])
        self.assertFalse((self.root / "bin").exists())
        self.assertFalse((self.root / "data").exists())

    def test_ambiguous_registration_preserves_action_files(self):
        def scheduled(*args):
            return subprocess.CompletedProcess(args, 1, stdout=b"")
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "task_absent", return_value=False):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_REGISTRATION_AMBIGUOUS")
        self.assertTrue((self.root / "bin" / activation.RUNNER_FILES[0]).is_file())

    def test_task_readback_mismatch_deletes_only_new_task(self):
        observed = []
        def scheduled(*args):
            observed.append(args[0])
            raw = b"<Task/>" if args[0] == "/Query" else b""
            return subprocess.CompletedProcess(args, 0, stdout=raw)
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "task_absent", return_value=True), \
                patch.object(activation, "listener_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "task_readback")
        self.assertEqual(observed, ["/Create", "/Query", "/End", "/Delete"])
        self.assertFalse((self.root / "bin").exists())
        self.assertFalse((self.root / "data").exists())

    def test_unattributed_listener_never_receives_token(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        with patch.object(activation, "listener_owned_by_task", return_value=False), \
                patch.object(activation, "http_status") as http:
            self.assertFalse(activation.verify_api(self.token, python, runner))
            http.assert_not_called()

    def test_service_not_ready_removes_task_and_new_files(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        observed = []
        def scheduled(*args):
            observed.append(args[0])
            raw = activation.task_xml(python, runner, self.user) if args[0] == "/Query" else b""
            return subprocess.CompletedProcess(args, 0, stdout=raw)
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "wait_api", return_value=False), \
                patch.object(activation, "task_absent", return_value=True), \
                patch.object(activation, "listener_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "api_readback")
        self.assertEqual(observed, ["/Create", "/Query", "/Run", "/End", "/Delete"])
        self.assertFalse((self.root / "bin").exists())
        self.assertFalse((self.root / "data").exists())


if __name__ == "__main__":
    unittest.main()
