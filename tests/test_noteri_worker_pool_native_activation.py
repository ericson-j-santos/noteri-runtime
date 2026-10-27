from __future__ import annotations

import getpass
import json
import socket
import subprocess
import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

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
        admin = patch.object(activation, "is_admin", return_value=True)
        admin.start()
        self.addCleanup(admin.stop)

    def test_unelevated_activation_stops_before_writing(self):
        with patch.object(activation, "is_admin", return_value=False), \
                patch.object(activation, "qualify") as qualify:
            with self.assertRaisesRegex(activation.Blocked, "elevation_required"):
                activation.activate(self.path, self.source)
            qualify.assert_not_called()
        self.assertFalse((self.root / "bin").exists())

    def test_xml_requires_limited_s4u_boot_and_exact_action(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        raw = activation.task_xml(python, runner, self.user)
        self.assertTrue(activation.task_matches(raw, python, runner, self.user))
        mislabeled = raw.replace(b"encoding='utf-8'", b'encoding="UTF-16"')
        self.assertTrue(activation.task_matches(mislabeled, python, runner, self.user))
        altered = raw.replace(b"S4U", b"InteractiveToken")
        self.assertFalse(activation.task_matches(altered, python, runner, self.user))
        sid_export = raw.replace(self.user.encode(), b"S-1-5-21-12345")
        with patch.object(activation, "account_sid", return_value="S-1-5-21-12345"):
            self.assertTrue(activation.task_matches(sid_export, python, runner, self.user))
        short_name_export = raw.replace(self.user.encode(), b"short-name")
        with patch.object(activation, "account_sid", return_value="S-1-5-21-12345"):
            self.assertTrue(activation.task_matches(short_name_export, python, runner,
                                                    self.user))
        self.assertIn(b"LeastPrivilege", raw)
        self.assertIn(b"BootTrigger", raw)

    def test_com_registration_uses_limited_s4u_without_password(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        service = MagicMock()
        folder = service.GetFolder.return_value
        definition = service.NewTask.return_value
        client = types.ModuleType("win32com.client")
        client.Dispatch = MagicMock(return_value=service)
        package = types.ModuleType("win32com")
        package.client = client
        with patch.dict(sys.modules, {"win32com": package, "win32com.client": client}), \
                patch.object(activation.site, "addsitedir"), \
                patch.object(activation, "account_sid", return_value="S-1-5-21-12345"):
            result = activation.register_task_com(python, runner, self.user,
                                                   self.root / "control")
        self.assertEqual(result.returncode, 0)
        folder.RegisterTaskDefinition.assert_called_once_with(
            "NoteriWorkerPoolApi", definition, 2, "S-1-5-21-12345", None, 2)
        self.assertEqual(definition.Principal.UserId, "S-1-5-21-12345")
        self.assertEqual(definition.Principal.LogonType, 2)
        self.assertEqual(definition.Principal.RunLevel, 0)
        self.assertEqual(definition.Triggers.Create.call_args.args, (8,))
        self.assertEqual(definition.Actions.Create.call_args.args, (0,))

    def test_com_readback_resolves_local_alias_and_rejects_changed_action(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        service = MagicMock()
        definition = activation.build_task_definition(service, python, runner, self.user)
        trigger = definition.Triggers.Create.return_value
        trigger.Type = 8
        definition.Triggers.Count = 1
        definition.Triggers.Item.return_value = trigger
        action = definition.Actions.Create.return_value
        action.Type = 0
        definition.Actions.Count = 1
        definition.Actions.Item.return_value = action
        definition.Principal.UserId = getpass.getuser()

        def local_sid(name):
            if name != self.user:
                raise activation.Blocked("unknown account")
            return "S-1-5-21-12345"

        with patch.object(activation, "account_sid", side_effect=local_sid):
            self.assertEqual(activation.task_definition_mismatches(
                definition, python, runner, self.user), [])
            definition.Principal.RunLevel = 1
            action.Path = str(self.path / "other.exe")
            self.assertEqual(activation.task_definition_mismatches(
                definition, python, runner, self.user), ["run_level", "action_path"])

    def test_register_readback_and_health_success(self):
        python = self.venv / "Scripts" / "python.exe"
        runner = self.root / "bin" / activation.RUNNER_FILES[0]
        observed = []
        def scheduled(*args):
            observed.append(args[0])
            raw = activation.task_xml(python, runner, self.user) if args[0] == "/Query" else b""
            return subprocess.CompletedProcess(args, 0, stdout=raw)
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "register_task_com", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(activation, "task_com_mismatches", return_value=[]), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "wait_api", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "API_ACTIVATED")
        self.assertEqual(observed, ["/Run"])
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
                patch.object(activation, "register_task_com", return_value=subprocess.CompletedProcess(
                    [], 1, stdout=b"", stderr=b"Access is denied")), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "task_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "register")
        self.assertEqual(observed, ["/Query"])
        self.assertFalse((self.root / "bin").exists())
        self.assertFalse((self.root / "data").exists())
        diagnostic = self.root / f"registration-failure-{result['diagnostic_id']}.json"
        self.assertEqual(json.loads(diagnostic.read_text())["stderr"], "Access is denied")
        self.assertNotIn("Access is denied", str(result))

    def test_ambiguous_registration_preserves_action_files(self):
        def scheduled(*args):
            return subprocess.CompletedProcess(args, 1, stdout=b"")
        with patch.object(activation, "qualify", return_value=(self.root, self.venv, self.token)), \
                patch.object(activation, "register_task_com", return_value=subprocess.CompletedProcess([], 1)), \
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
                patch.object(activation, "register_task_com", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(activation, "task_com_mismatches", return_value=["principal"]), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "task_absent", return_value=True), \
                patch.object(activation, "listener_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "task_readback")
        self.assertEqual(observed, ["/End", "/Delete"])
        diagnostic = self.root / f"task-readback-failure-{result['diagnostic_id']}.json"
        self.assertEqual(json.loads(diagnostic.read_text())["fields"], ["principal"])
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
                patch.object(activation, "register_task_com", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(activation, "task_com_mismatches", return_value=[]), \
                patch.object(activation, "schtasks", side_effect=scheduled), \
                patch.object(activation, "wait_api", return_value=False), \
                patch.object(activation, "task_absent", return_value=True), \
                patch.object(activation, "listener_absent", return_value=True):
            result = activation.activate(self.path, self.source)
        self.assertEqual(result["result"], "BLOCKED_ACTIVATION_ROLLED_BACK")
        self.assertEqual(result["phase"], "api_readback")
        self.assertEqual(observed, ["/Run", "/End", "/Delete"])
        self.assertFalse((self.root / "bin").exists())
        self.assertFalse((self.root / "data").exists())


if __name__ == "__main__":
    unittest.main()
