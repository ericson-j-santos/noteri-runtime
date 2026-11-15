"""Tests of the Noteri Ollama read-only process and loopback inventory."""
from __future__ import annotations

import importlib.util
import errno
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_watchdog_readonly_inventory.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("noteri_ollama_inventory_under_test", SOURCE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestOllamaReadonlyTransport(unittest.TestCase):
    def tasklist(self, content: str, returncode: int = 0) -> str:
        observed = SimpleNamespace(stdout=content, returncode=returncode)
        with patch.object(Path, "is_file", return_value=True), patch.object(
            module.subprocess, "run", return_value=observed
        ) as run:
            status = module.ollama_process_state()
        run.assert_called_once()
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[1:], ["/FO", "CSV", "/NH"])
        self.assertTrue(str(arguments[0]).lower().endswith("system32\\tasklist.exe") or
                        str(arguments[0]).lower().endswith("system32/tasklist.exe"))
        return status

    def test_ollama_process_present(self):
        self.assertEqual(
            self.tasklist('"System","4","Services"\n"ollama.exe","123","Console"\n'),
            "PRESENT",
        )

    def test_ollama_process_absent(self):
        self.assertEqual(self.tasklist('"System","4","Services"\n'), "ABSENT")

    def test_tasklist_failure_is_unknown(self):
        self.assertEqual(self.tasklist("", returncode=1), "UNKNOWN")
        self.assertEqual(self.tasklist("INFO: access denied\n"), "UNKNOWN")
        self.assertEqual(self.tasklist('"ollama.exe","not-an-id"\n'), "UNKNOWN")

    def test_process_inspection_never_launches_ollama(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(
            module.subprocess, "run", side_effect=OSError("denied")
        ):
            self.assertEqual(module.ollama_process_state(), "UNKNOWN")

    def tcp(self, code: int) -> str:
        fake = MagicMock()
        fake.__enter__.return_value.connect_ex.return_value = code
        with patch.object(module.socket, "socket", return_value=fake) as ctor:
            result = module.ollama_port_state()
        ctor.assert_called_once_with(module.socket.AF_INET, module.socket.SOCK_STREAM)
        fake.__enter__.return_value.connect_ex.assert_called_once_with(("127.0.0.1", 11434))
        return result

    def test_fixed_loopback_open_and_closed(self):
        self.assertEqual(self.tcp(0), "OPEN")
        self.assertEqual(self.tcp(errno.ECONNREFUSED), "CLOSED")
        self.assertEqual(self.tcp(10061), "CLOSED")

    def test_unknown_network_error_fails_closed(self):
        self.assertEqual(self.tcp(10013), "UNKNOWN")
        with patch.object(module.socket, "socket", side_effect=OSError("blocked")):
            self.assertEqual(module.ollama_port_state(), "UNKNOWN")

    def test_result_contains_separate_transport_evidence(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('"ollama_transport": transport', source)
        self.assertNotIn("subprocess.Popen", source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()
