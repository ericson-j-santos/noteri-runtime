"""Positive/negative tests of read-only, fixed Python pytest metadata probe."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_python_pytest_inventory_readonly as probe


class ProbeTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.python = Path(t.name) / "python.exe"
        self.python.write_bytes(b"fixture-only-not-an-executable")

    def test_direct_cli_help_imports_without_pythonpath(self):
        script = (Path(__file__).resolve().parents[1] / "scripts"
                  / "noteri_python_pytest_inventory_readonly.py")
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        completed = subprocess.run(
            [sys.executable, "-B", str(script), "--help"],
            cwd=script.parents[1], env=environment,
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=12, check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("--expected-head", completed.stdout)

    def test_fixed_probe_is_valid_python_and_does_not_import_pytest(self):
        compile(probe.PROBE_CODE, "fixed_pytest_metadata_probe", "exec")
        self.assertIn("importlib.metadata", probe.PROBE_CODE)
        self.assertNotIn("import pytest", probe.PROBE_CODE)

    def test_pytest_found_reports_only_sanitized_version(self):
        doc = {"python":"3.11","pytest":"8.4.2"}
        with patch.object(probe.subprocess, "run",
                          return_value=SimpleNamespace(
                              returncode=0, stdout=json.dumps(doc),
                              stderr="private")) as run:
            r=probe._probe("fixed", self.python)
        self.assertEqual(r["result"], "PYTEST_PRESENT")
        self.assertEqual(r["pytest_version"], "8.4.2")
        self.assertNotIn("private", json.dumps(r))
        cmd=run.call_args.args[0]
        self.assertEqual(cmd[1:4], ["-B", "-I", "-c"])
        self.assertNotIn("pip", cmd)

    def test_missing_pytest_is_not_claimed_as_available(self):
        with patch.object(probe.subprocess,"run",
                          return_value=SimpleNamespace(
                              returncode=0,
                              stdout='{"python":"3.14","pytest":null}',
                              stderr="")):
            r=probe._probe("fixed",self.python)
        self.assertEqual(r["result"],"PYTEST_MISSING")
        self.assertIsNone(r["pytest_version"])

    def test_bad_or_ambiguous_evidence_fails_closed(self):
        for text in ('{"python":"3.14","pytest":null,"token":"bad"}',
                     '{"python":"3.14","pytest":"../not-allowed"}',
                     "not-json"):
            with self.subTest(text=text):
                with patch.object(probe.subprocess,"run",
                                  return_value=SimpleNamespace(
                                      returncode=0, stdout=text, stderr="")):
                    r=probe._probe("fixed",self.python)
                self.assertNotEqual(r["result"],"PYTEST_PRESENT")


if __name__ == "__main__":
    unittest.main()
