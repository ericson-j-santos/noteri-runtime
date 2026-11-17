"""Rules #219 source-pin and host observation tests. No physical Noteri calls."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import noteri_rules219_readonly_admission as gate


class ReadonlyPinsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "file.py").write_text("VERSION = 1\n", encoding="utf-8")
        self.git("add", "--all")
        self.git("-c", "user.name=IsolatedTest",
                 "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "source")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "--detach", "-q", self.sha)
        self.git("remote", "add", "origin",
                 "https://github.com/ericson-j-santos/noteri-runtime.git")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args],
                              capture_output=True, check=True, text=True).stdout

    def test_real_git_detached_clean_source_positive(self):
        gate.verify_checkout(self.repo, repository=gate.NOTERI_REPO, sha=self.sha)

    def test_wrong_commit_fails(self):
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_SHA_DRIFT"):
            gate.verify_checkout(self.repo, repository=gate.NOTERI_REPO,
                                 sha="0" * 40)

    def test_wrong_remote_fails(self):
        self.git("remote", "set-url", "origin", "https://example.invalid/repo.git")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_ORIGIN_DRIFT"):
            gate.verify_checkout(self.repo, repository=gate.NOTERI_REPO, sha=self.sha)

    def test_local_branch_fails(self):
        self.git("switch", "-q", "-c", "candidate")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_SHA_DRIFT"):
            gate.verify_checkout(self.repo, repository=gate.NOTERI_REPO, sha=self.sha)

    def test_tracked_mutation_fails(self):
        (self.repo / "file.py").write_text("CHANGED = 1\n", encoding="utf-8")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_TRACKED_DIRTY"):
            gate.verify_checkout(self.repo, repository=gate.NOTERI_REPO, sha=self.sha)

    def test_rules_checkout_untracked_file_fails_closed(self):
        self.git("remote", "set-url", "origin",
                 "https://github.com/ericson-j-santos/chatgpt-operational-rules.git")
        (self.repo / "extra.py").write_text("unexpected = True\n")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_UNTRACKED"):
            gate.verify_checkout(self.repo, repository=gate.RULES_REPO, sha=self.sha)

    def test_git_object_and_source_bytes_match(self):
        data = (self.repo / "file.py").read_bytes()
        gate.verify_file(self.repo, "file.py",
                         digest=hashlib.sha256(data).hexdigest())

    def test_untracked_spoof_of_file_does_not_pass_hash(self):
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_FILE_DIGEST_DRIFT"):
            gate.verify_file(self.repo, "file.py", digest="f" * 64)

    def test_staged_file_divergence_detected(self):
        old_digest = hashlib.sha256((self.repo / "file.py").read_bytes()).hexdigest()
        (self.repo / "file.py").write_text("CHANGED = 1\n")
        self.git("add", "file.py")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_FILE_DIGEST_DRIFT"):
            gate.verify_file(self.repo, "file.py", digest=old_digest)

    def test_symlink_is_never_source(self):
        path = self.repo / "link.py"
        try:
            path.symlink_to(self.repo / "file.py")
        except (NotImplementedError, OSError):
            self.skipTest("Symlink support unavailable")
        with self.assertRaisesRegex(gate.Blocked, "SOURCE_FILE_INVALID"):
            gate.verify_file(self.repo, "link.py", digest="0" * 64)


class ReadonlyContextTests(unittest.TestCase):
    def setUp(self):
        self.ctx = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": gate.NOTERI_REPO,
            "RUNNER_NAME": "Noteri-runtime",
            "GITHUB_SHA": "a" * 40,
            "SESSION_LAUNCH_RESULT": "SESSION_LAUNCH_OK",
            "SESSION_STATE_VALIDATED": "true",
            "SESSION_GATEWAY_BOUND": "true",
            "SESSION_SNAPSHOT_SHA256": "b" * 64,
        }

    def test_session_schema_positive_is_not_host_attestation(self):
        gate.context_observed(self.ctx, host_name="Noteri", platform="nt",
                              expected_host_sha="a" * 40)

    def test_other_host_or_mode_is_rejected(self):
        for name, platform in (("Other", "nt"), ("Noteri", "posix")):
            with self.subTest(name=name, platform=platform):
                with self.assertRaisesRegex(gate.Blocked, "HOST_CONTEXT_INVALID"):
                    gate.context_observed(self.ctx, host_name=name, platform=platform,
                                          expected_host_sha="a" * 40)

    def test_missing_or_forged_session_flag_is_rejected(self):
        for key, value in (
            ("SESSION_LAUNCH_RESULT", "BOOTSTRAP_OK"),
            ("SESSION_STATE_VALIDATED", "false"),
            ("SESSION_GATEWAY_BOUND", ""),
            ("SESSION_SNAPSHOT_SHA256", ""),
            ("GITHUB_SHA", "c" * 40),
        ):
            with self.subTest(key=key):
                ctx = {**self.ctx, key: value}
                with self.assertRaisesRegex(gate.Blocked, "SESSION_CONTEXT_UNATTESTED"):
                    gate.context_observed(ctx, host_name="Noteri", platform="nt",
                                          expected_host_sha="a" * 40)

    def test_local_exact_model_tag_and_digest_only(self):
        self.assertEqual(gate.inspect_model_tags({
            "models": [{"name": gate.MODEL, "digest": "d" * 64}],
        }), "d" * 64)

    def test_model_missing_remote_or_duplicate_rejected(self):
        fixtures = (
            {"models": []},
            {"models": [{"name": gate.MODEL, "digest": "invalid"}]},
            {"models": [{"name": gate.MODEL, "digest": "d" * 64,
                         "remote_host": "cloud"}]},
            {"models": [
                {"name": gate.MODEL, "digest": "d" * 64},
                {"name": gate.MODEL, "digest": "d" * 64},
            ]},
        )
        for v in fixtures:
            with self.subTest(payload=v):
                with self.assertRaises(gate.Blocked):
                    gate.inspect_model_tags(v)

    def test_no_synthetic_context_can_produce_ready_true(self):
        with mock.patch.object(gate, "verify_pins", return_value={
            "rules_sha": gate.RULES_SHA, "worker_sha": gate.POOL_SHA,
            "host_sha": "a" * 40, "source_pins_verified": True,
            "script_count": 4,
        }) as observe:
            result = gate.inspect_readonly(
                env=self.ctx,
                host=Path("/fake-host"), rules=Path("/fake-rules"),
                pool=Path("/fake-pool"),
                tags={"models": [{"name": gate.MODEL, "digest": "d" * 64}]},
                host_name="Noteri", platform="nt",
            )
        observe.assert_called_once()
        self.assertEqual(result["result"], "NOTERI_219_READONLY_OBSERVATIONS")
        for key in ("ready_for_builder", "gateway_execution_attested",
                    "cost_zero_attested", "lease_attested",
                    "artifact_cas_attested", "activation_authorized",
                    "builder_executed", "state_changed", "secrets_read"):
            self.assertIs(result[key], False)

    def test_source_drift_prevents_even_local_ollama_read(self):
        with mock.patch.object(gate, "verify_pins",
                               side_effect=gate.Blocked("NOTERI_219_SOURCE_SHA_DRIFT")):
            local_get = mock.Mock()
            with self.assertRaisesRegex(gate.Blocked, "SOURCE_SHA_DRIFT"):
                gate.inspect_readonly(
                    env=self.ctx,
                    host=Path("/fake-host"), rules=Path("/fake-rules"),
                    pool=Path("/fake-pool"), tags=local_get,
                    host_name="Noteri", platform="nt",
                )
            local_get.assert_not_called()

    def test_loopback_inventory_exact_get_no_proxy_or_redirect(self):
        class FakeResponse:
            status = 200
            def geturl(self):
                return "http://127.0.0.1:11434/api/tags"
            def read(self, size):
                self_read = b'{"models":[{"name":"qwen2.5-coder:7b","digest":"' + b'd' * 64 + b'"}]}'
                return self_read
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        class FakeOpener:
            def open(self, url, timeout):
                self_url = "http://127.0.0.1:11434/api/tags"
                if url != self_url or timeout != 12:
                    raise AssertionError("Unexpected network request")
                return FakeResponse()

        with mock.patch.object(gate.urllib.request, "build_opener",
                               return_value=FakeOpener()) as mk:
            data = gate.local_model_inventory()
            self.assertEqual(gate.inspect_model_tags(data), "d" * 64)
        self.assertEqual(mk.call_count, 1)

    def test_main_without_host_context_stops_before_any_model_access(self):
        with mock.patch.object(sys, "argv", ["readonly.py"]):
            with mock.patch.dict(os.environ, {}, clear=True):
                with mock.patch.object(gate, "local_model_inventory") as network:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        result = gate.main()
        self.assertEqual(result, 2)
        self.assertFalse(json.loads(output.getvalue())["ready_for_builder"])
        network.assert_not_called()

    def test_main_rejects_extra_arguments(self):
        with mock.patch.object(sys, "argv", ["readonly.py", "--activate"]):
            with self.assertRaisesRegex(SystemExit, "ARGUMENTS_FORBIDDEN"):
                gate.main()



class WorkflowBindingTests(unittest.TestCase):
    """Static regression guards for the existing owner-only physical entrypoint."""

    @classmethod
    def setUpClass(cls):
        cls.workflow = (Path(__file__).resolve().parents[1] /
                        ".github/workflows/noteri-control-plane-probe.yml").read_text(
                            encoding="utf-8")

    def test_legacy_mode_still_explicit_and_default(self):
        self.assertIn("default: qualification", self.workflow)
        self.assertIn("inputs.mode == 'qualification'", self.workflow)
        self.assertIn("PROBE-NOTERI-CONTROL-PLANE", self.workflow)

    def test_physical_mode_owner_main_manual_only(self):
        path = self.workflow.split("\n  rules219_probe:", 1)[1].split(
            "\n  rules219_independent:", 1)[0]
        for required in (
            "github.actor == 'ericson-j-santos'",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'workflow_dispatch'",
            "inputs.mode == 'rules219_readonly'",
            "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]",
            "'SESSION_LAUNCH_OK'", "'--risk', '1'",
            "'--require-runner-version-preflight'",
            "noteri_rules219_readonly_admission.py",
            "NOTERI_219_PHYSICAL_READONLY_RECEIPT_OK",
        ):
            self.assertIn(required, path)
        self.assertNotIn("'--risk', '2'", path)
        self.assertNotIn("upload-artifact", path)
        self.assertNotIn("ollama run", path)

    def test_pinned_sources_and_independent_readback(self):
        for sha in (gate.RULES_SHA, gate.POOL_SHA,
                    "58dcd4200f412a866278027ba9e433439a03f3b3"):
            self.assertIn(sha, self.workflow)
        independent = self.workflow.split("\n  rules219_independent:", 1)[1]
        self.assertIn("needs: rules219_probe", independent)
        self.assertIn("runner_name !== 'Noteri-runtime'", independent)
        self.assertIn("NOTERI_219_INDEPENDENT_READBACK_OK_READY_FALSE", independent)
        self.assertIn('"ready_for_builder": False', independent)
        self.assertIn('"cost_zero_attested": False', independent)
        self.assertIn('"activation_authorized": False', independent)
        self.assertIn('"state_changed": False', independent)

    def test_ci_runs_when_physical_workflow_changes(self):
        contract = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/noteri-rules219-readonly-contract.yml").read_text(
                        encoding="utf-8")
        trigger_paths = contract.split("\n    paths:\n", 1)[1].split(
            "\n\npermissions:\n", 1)[0].splitlines()
        self.assertIn(
            "      - .github/workflows/noteri-control-plane-probe.yml",
            trigger_paths,
        )
        self.assertEqual(trigger_paths.count(
            "      - .github/workflows/noteri-control-plane-probe.yml"), 1)

    def test_no_automatic_physical_dispatch(self):
        header = self.workflow.split("\njobs:", 1)[0]
        self.assertIn("workflow_dispatch:", header)
        self.assertNotIn("push:", header)
        self.assertNotIn("schedule:", header)
        self.assertNotIn("workflow_call:", header)


if __name__ == "__main__":
    unittest.main()
