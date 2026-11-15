"""No-command/no-download tests for fixed existing-pytest regression runner."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_worker_pool_existing_pytest_six_regressions as m


class SixSuitesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        for relative in m.FILES:
            target=self.root/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text("def test_fixture(): assert True\n",encoding="utf-8")
        self.python=self.root/"pinned-python.exe"
        self.python.write_bytes(b"not-real-executable")
        self.interpreter={"label":"worker_pool_pinned_venv",
                          "result":"PYTEST_PRESENT",
                          "pytest_version":"9.0.3","python_version":"3.11"}

    def test_six_exact_test_files_present_and_no_arbitrary_path(self):
        self.assertEqual(len(m.FILES),6)
        self.assertTrue(all(x.startswith("tests/") for x in m.FILES))
        self.assertEqual(len(m._fixed_test_paths(self.root)),6)

    def test_fail_closed_without_preexisting_verified_interpreter(self):
        with patch.object(m,"_validated_candidates",return_value={}):
            with self.assertRaisesRegex(m.Blocked,"VERIFIED_PYTEST_VENV_NOT_FOUND"):
                m.run(self.root,local=self.root,roaming=self.root)

    def test_fail_closed_on_pytest_version_drift(self):
        with patch.object(m,"_validated_candidates",return_value={
            "worker_pool_pinned_venv":self.python}), patch.object(
                m,"_probe",return_value={**self.interpreter,
                                       "pytest_version":"0.0.0"}):
            with self.assertRaisesRegex(m.Blocked,"VERSION_MISMATCH"):
                m.run(self.root,local=self.root,roaming=self.root)

    def test_sanitized_success_runs_only_explicit_six_tests(self):
        fake=SimpleNamespace(returncode=0,stdout="123 passed in 0.35s\n",stderr="")
        with patch.object(m,"_validated_candidates",return_value={
            "worker_pool_pinned_venv":self.python}), patch.object(
                m,"_probe",return_value=self.interpreter), patch.object(
                m.subprocess,"run",return_value=fake) as executed:
            result=m.run(self.root,local=self.root,roaming=self.root)
        self.assertEqual(result["result"],"PYTEST_SIX_SUITES_PASSED")
        self.assertEqual(result["test_files"],6)
        argv=executed.call_args.args[0]
        self.assertEqual(argv[1:4],["-B","-I","-m"])
        self.assertEqual(argv[-6:],list(m.FILES))
        self.assertNotIn("pip",argv)
        self.assertEqual(executed.call_args.kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"],"1")

    def test_skipped_and_failed_tests_do_not_qualify(self):
        for text,exitcode in (("7 passed, 1 skipped in 0.4s",0),
                              ("7 passed, 1 failed in 0.4s",1),
                              ("no tests ran",5)):
            with self.subTest(text=text):
                fake=SimpleNamespace(returncode=exitcode,stdout=text,stderr="")
                with patch.object(m,"_validated_candidates",return_value={
                    "worker_pool_pinned_venv":self.python}), patch.object(
                    m,"_probe",return_value=self.interpreter),patch.object(
                    m.subprocess,"run",return_value=fake):
                    result=m.run(self.root,local=self.root,roaming=self.root)
                self.assertEqual(result["result"],"PYTEST_PARTIAL_OR_FAILED")

    def test_cli_help_imports_without_pythonpath(self):
        script=(Path(__file__).resolve().parents[1]/"scripts"
                /"noteri_worker_pool_existing_pytest_six_regressions.py")
        env=dict(os.environ)
        env.pop("PYTHONPATH",None)
        r=subprocess.run([sys.executable,"-B",str(script),"--help"],
                         cwd=script.parents[1],env=env,
                         capture_output=True,text=True,timeout=12,check=False)
        self.assertEqual(r.returncode,0)
        self.assertIn("--expected-head",r.stdout)


if __name__=="__main__":
    unittest.main()
