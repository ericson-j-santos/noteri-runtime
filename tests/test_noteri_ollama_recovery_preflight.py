"""Controles negativos e positivos para o plano Ollama, sem executar serviço."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "noteri_ollama_recovery_preflight", ROOT / "scripts/noteri_ollama_recovery_preflight.py"
)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

SHA = "e" * 40


class PlanTests(unittest.TestCase):
    def invoke(self, *, host="Noteri", platform="nt", profile="NORMAL",
               process="ABSENT", port="CLOSED", candidate_count=1, listener="ABSENT"):
        found = [
            {"candidate": "a", "status": "PRESENT" if i < candidate_count else "MISSING",
             "sha256": "a"*64, "bytes": 42}
            for i in range(3)
        ]
        with patch.object(m, "inspect_windows_listener", return_value=listener), \
             patch.object(m, "source_sha", return_value=SHA), \
             patch.object(m, "candidate", side_effect=found), \
             patch.object(m, "ollama_process_state", return_value=process), \
             patch.object(m, "ollama_port_state", return_value=port), \
             patch.object(m, "read_model_tags", return_value={"status": "PRESENT"}):
            return m.plan(expected_sha=SHA, correlation_id="noteri-ollama-test-20261115",
                          confirm=m.CONFIRM, host=host, platform=platform,
                          root=ROOT, profile=profile)

    def test_single_fixed_candidate_is_still_no_start(self):
        value = self.invoke()
        self.assertEqual(value["status"], "PREFLIGHT_CANDIDATE")
        self.assertFalse(value["recovery_authorized"])
        self.assertFalse(value["restart_performed"])
        self.assertFalse(value["state_changed"])
        self.assertEqual(value["api"]["status"], "NOT_QUERIED")

    def test_unknown_port_with_verified_no_listener_is_only_candidate(self):
        value = self.invoke(port="UNKNOWN")
        self.assertEqual(value["windows_tcp_listener"], "ABSENT")
        self.assertEqual(value["status"], "PREFLIGHT_CANDIDATE")
        self.assertFalse(value["recovery_authorized"])

    def test_unknown_os_listener_does_not_admit(self):
        self.assertEqual(self.invoke(port="UNKNOWN", listener="UNKNOWN")["status"], "BLOCKED_OR_INCONCLUSIVE")

    def test_process_existing_does_not_admit_start(self):
        self.assertEqual(self.invoke(process="PRESENT")["status"], "BLOCKED_OR_INCONCLUSIVE")

    def test_missing_and_multiple_executables_block(self):
        self.assertEqual(self.invoke(candidate_count=0)["status"], "BLOCKED_OR_INCONCLUSIVE")
        self.assertEqual(self.invoke(candidate_count=2)["status"], "BLOCKED_OR_INCONCLUSIVE")

    def test_host_and_profile_fail_closed(self):
        for overrides in ({"host":"Desktop"}, {"platform":"posix"}, {"profile":"ESTUDO"}):
            with self.assertRaises(m.PlanBlocked):
                self.invoke(**overrides)

    def test_fixed_confirmation_required(self):
        with self.assertRaises(m.PlanBlocked):
            m.plan(expected_sha=SHA, correlation_id="noteri-ollama-test-20261115",
                   confirm="WRONG", host="Noteri", platform="nt",
                   root=ROOT, profile="NORMAL")

    def test_nonexistent_candidate(self):
        with patch.object(m.os, "path") as _unused:
            pass
        value = m.candidate("CHECK", ROOT, "missing/ollama.exe")
        self.assertEqual(value["status"], "MISSING")

    def test_reject_redirected_candidate(self):
        with patch.object(m, "path_safe", return_value=False):
            value = m.candidate("CHECK", ROOT, "ollama.exe")
        self.assertEqual(value["status"], "UNSAFE")

    def test_no_mutating_process_calls_in_source(self):
        raw = (ROOT / "scripts/noteri_ollama_recovery_preflight.py").read_text()
        for forbidden in ("subprocess.Popen", "os.system(", "startfile(", "shell=True",
                          "ollama pull", "Start-Service", "Restart-Service"):
            self.assertNotIn(forbidden, raw)
        self.assertIn('"recovery_authorized": False', raw)


if __name__ == "__main__":
    unittest.main()
