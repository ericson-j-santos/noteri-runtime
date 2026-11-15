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
        self.assertEqual(argv[1:4],["-B","-I","-c"])
        self.assertEqual(argv[4], m.PYTEST_BRIDGE)
        self.assertIn("sys.path.insert(0,str(root))", argv[4])
        compile(argv[4], "fixed_isolated_pytest_bridge", "exec")
        self.assertEqual(argv[-6:],list(m.FILES))
        self.assertNotIn("pip",argv)
        self.assertEqual(executed.call_args.kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"],"1")
        runtime_env = executed.call_args.kwargs["env"]
        if os.name == "nt":
            trusted = (Path(os.environ.get("SYSTEMROOT", "C:\\Windows")) /
                       "System32" / "WindowsPowerShell" / "v1.0")
            self.assertEqual(runtime_env["PATH"], str(trusted))
        else:
            self.assertNotIn("PATH", runtime_env)


    def test_windows_missing_powershell_blocks_before_test_process(self):
        if os.name != "nt":
            self.skipTest("Requires Windows system-root validation")
        with patch.dict(os.environ, {"SYSTEMROOT": str(self.root)}), patch.object(
            m, "_validated_candidates", return_value={
                "worker_pool_pinned_venv": self.python
            }), patch.object(m, "_probe", return_value=self.interpreter), patch.object(
                m.subprocess, "run"
            ) as process:
            with self.assertRaisesRegex(m.Blocked, "WINDOWS_POWERSHELL_UNAVAILABLE"):
                m.run(self.root, local=self.root, roaming=self.root)
            process.assert_not_called()

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

    def test_collection_error_classifier_redacts_unexpected_module_names(self):
        trace = (
            "ERROR collecting tests/test_noteri_worker_pool_native_stage.py\\n"
            "E   ModuleNotFoundError: No module named 'scripts'\\n"
            "E   ModuleNotFoundError: No module named 'some_untrusted_token_label'\\n"
        )
        data=m._collection_diagnostics(trace)
        self.assertTrue(data["collection_error_detected"])
        self.assertEqual(data["missing_known_modules"], ["scripts"])
        self.assertEqual(data["unrecognized_missing_module_count"], 1)
        self.assertNotIn("some_untrusted_token_label",str(data))

    def test_only_known_failed_test_ids_and_safe_classes_escape(self):
        text = (
            "FAILED tests/test_noteri_worker_pool_native_stage.py::"
            "test_repro - AssertionError: private-content-123\\n"
            "FAILED tests/other_private_file.py::"
            "test_hidden - PermissionError: hidden\\n"
        )
        cases=m._failed_test_cases(text)
        self.assertEqual(cases,[{
            "file":"tests/test_noteri_worker_pool_native_stage.py",
            "case":"test_repro","failure_class":"AssertionError",
        }])
        self.assertNotIn("private-content-123",str(cases))
        self.assertNotIn("other_private_file",str(cases))

    def test_twenty_parametrized_failures_are_counted_without_private_values(self):
        source = "tests/test_noteri_worker_pool_native_stage.py"
        lines = [
            f"FAILED {source}::Suite::test_context_and_activation_are_denied_before_writes"
            f"[private value {i} /sensitive::token] - AssertionError: hidden-payload"
            for i in range(20)
        ]
        failed = m._failed_test_cases("\n".join(lines) + "\n66 passed, 20 failed\n")
        self.assertEqual(len(failed), 20)
        self.assertEqual(len({case["case"] for case in failed}), 20)
        self.assertTrue(all(case["file"] == source for case in failed))
        self.assertTrue(all(case["failure_class"] == "AssertionError" for case in failed))
        self.assertTrue(all(case["case"].startswith(
            "test_context_and_activation_are_denied_before_writes-"
        ) for case in failed))
        self.assertNotIn("sensitive", str(failed))
        self.assertNotIn("private value", str(failed))
        self.assertNotIn("hidden-payload", str(failed))

    def test_unknown_failure_class_and_foreign_path_stay_redacted(self):
        text = "\n".join([
            "FAILED tests/test_noteri_worker_pool_native_stage.py::"
            "test_repro[secret /path] - assert 1 == 2",
            "FAILED tests/private_unapproved.py::"
            "test_hidden - AssertionError: private",
        ])
        cases = m._failed_test_cases(text)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["failure_class"], "UNCLASSIFIED_FAILURE")
        self.assertTrue(cases[0]["case"].startswith("test_repro-"))
        self.assertNotIn("secret", str(cases))
        self.assertNotIn("private_unapproved.py", str(cases))

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
