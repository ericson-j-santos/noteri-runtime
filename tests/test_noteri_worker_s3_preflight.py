"""Offline contract tests for the physical Noteri S3 preflight."""
from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_worker_s3_credentials as credentials
import noteri_worker_s3_preflight as p


RUNTIME_SHA = "1" * 40
RUNTIME_TREE = "2" * 40
WORKER_SHA = "3" * 40
WORKER_TREE = "4" * 40
SECRET = "TEST-ONLY-MUST-NEVER-BE-EMITTED"


class FakeConfig:
    def __init__(self, **values: object):
        self.values = values


class FakeTransport:
    calls = 0

    def __init__(self, config: FakeConfig, client: object):
        self.config = config
        self.client = client

    def preflight(self) -> None:
        type(self).calls += 1


class FailingTransport(FakeTransport):
    def preflight(self) -> None:
        raise RuntimeError(SECRET)


class NoteriWorkerS3PreflightTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.worker = self.root / "worker"
        self.worker.mkdir()
        self.route = credentials.S3Route(
            bucket="private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        FakeTransport.calls = 0

    def verifier(
        self,
        root: Path,
        expected_head: str,
        expected_tree: str,
        kind: str,
    ) -> p.CheckoutIdentity:
        selected = p.REPOSITORY_ROOT if kind == "runtime" else self.worker
        self.assertEqual(Path(root), selected)
        expected = (
            (RUNTIME_SHA, RUNTIME_TREE)
            if kind == "runtime"
            else (WORKER_SHA, WORKER_TREE)
        )
        self.assertEqual((expected_head, expected_tree), expected)
        return p.CheckoutIdentity(selected.resolve(), expected_head, expected_tree)

    @staticmethod
    def credential_runner(
        route: credentials.S3Route,
        callback: object,
    ) -> None:
        callback(object(), route)

    def execute(self, transport_type: type[FakeTransport] = FakeTransport) -> dict[str, object]:
        return p.execute_preflight(
            expected_runtime_sha=RUNTIME_SHA,
            expected_runtime_tree=RUNTIME_TREE,
            worker_pool_root=self.worker,
            expected_worker_pool_sha=WORKER_SHA,
            expected_worker_pool_tree=WORKER_TREE,
            correlation_id="physical-preflight-001",
            route=self.route,
            checkout_verifier=self.verifier,
            contract_loader=lambda _checkout: p.WorkerTransportContract(
                FakeConfig,
                transport_type,
            ),
            credential_runner=self.credential_runner,
            host_verifier=lambda: None,
        )

    def test_explicit_client_runs_shared_transport_without_exposing_route(self) -> None:
        before = {
            key: value for key, value in os.environ.items() if key.upper().startswith("AWS_")
        }
        result = self.execute()
        rendered = json.dumps(result, sort_keys=True)
        after = {
            key: value for key, value in os.environ.items() if key.upper().startswith("AWS_")
        }
        self.assertEqual(FakeTransport.calls, 1)
        self.assertEqual(result["result"], "NOTERI_WORKER_S3_PREFLIGHT_PASSED")
        self.assertEqual(result["runtime_sha"], RUNTIME_SHA)
        self.assertEqual(result["worker_pool_sha"], WORKER_SHA)
        self.assertTrue(result["conditional_write_and_exact_readback"])
        self.assertFalse(result["s4u_identity_claimed_by_script"])
        self.assertNotIn(self.route.bucket, rendered)
        self.assertNotIn(self.route.endpoint_url, rendered)
        self.assertNotIn(self.route.key_prefix, rendered)
        self.assertEqual(after, before)

    def test_transport_and_credential_failures_are_sanitized(self) -> None:
        with self.assertRaisesRegex(p.PhysicalPreflightError, "s3_preflight_failed") as caught:
            self.execute(FailingTransport)
        self.assertNotIn(SECRET, str(caught.exception))

        def blocked(_route: credentials.S3Route, _callback: object) -> None:
            raise credentials.CredentialBootstrapError("s3_callback_failed")

        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "credential_operation_blocked",
        ):
            p.execute_preflight(
                expected_runtime_sha=RUNTIME_SHA,
                expected_runtime_tree=RUNTIME_TREE,
                worker_pool_root=self.worker,
                expected_worker_pool_sha=WORKER_SHA,
                expected_worker_pool_tree=WORKER_TREE,
                correlation_id="physical-preflight-002",
                route=self.route,
                checkout_verifier=self.verifier,
                contract_loader=lambda _checkout: p.WorkerTransportContract(
                    FakeConfig,
                    FakeTransport,
                ),
                credential_runner=blocked,
                host_verifier=lambda: None,
            )

    def test_run_and_readback_require_the_fixed_physical_host(self) -> None:
        def wrong_host() -> None:
            raise credentials.CredentialBootstrapError("fixed_windows_host_required")

        common = {
            "expected_runtime_sha": RUNTIME_SHA,
            "expected_runtime_tree": RUNTIME_TREE,
            "worker_pool_root": self.worker,
            "expected_worker_pool_sha": WORKER_SHA,
            "expected_worker_pool_tree": WORKER_TREE,
            "correlation_id": "physical-host-gate",
            "route": self.route,
            "checkout_verifier": lambda *_args: self.fail("checkout must not run"),
            "host_verifier": wrong_host,
        }
        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "credential_operation_blocked",
        ):
            p.execute_preflight(**common)
        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "credential_operation_blocked",
        ):
            p.execute_readback(evidence_path=self.root / "missing.json", **common)

    def test_missing_duplicate_or_wrong_route_callback_fails_closed(self) -> None:
        other_route = credentials.S3Route(
            bucket="other-private-artifacts",
            region="us-east-2",
            endpoint_url="https://storage.example.invalid",
            key_prefix="worker/checkpoints",
        )
        runners = (
            lambda _route, _callback: None,
            lambda route, callback: (callback(object(), route), callback(object(), route)),
            lambda _route, callback: callback(object(), other_route),
        )
        for runner in runners:
            with self.subTest(runner=runner), self.assertRaisesRegex(
                p.PhysicalPreflightError,
                "s3_preflight_failed",
            ):
                p.execute_preflight(
                    expected_runtime_sha=RUNTIME_SHA,
                    expected_runtime_tree=RUNTIME_TREE,
                    worker_pool_root=self.worker,
                    expected_worker_pool_sha=WORKER_SHA,
                    expected_worker_pool_tree=WORKER_TREE,
                    correlation_id="physical-preflight-callback-control",
                    route=self.route,
                    checkout_verifier=self.verifier,
                    contract_loader=lambda _checkout: p.WorkerTransportContract(
                        FakeConfig,
                        FakeTransport,
                    ),
                    credential_runner=runner,
                    host_verifier=lambda: None,
                )

    def test_aws_environment_mutation_is_restored_and_blocked(self) -> None:
        marker = "AWS_TEST_ONLY_PREFLIGHT_MUTATION"
        original = os.environ.get(marker)

        def mutating(route: credentials.S3Route, callback: object) -> None:
            callback(object(), route)
            os.environ[marker] = "unexpected"

        try:
            with self.assertRaisesRegex(
                p.PhysicalPreflightError,
                "aws_environment_mutated",
            ):
                p.execute_preflight(
                    expected_runtime_sha=RUNTIME_SHA,
                    expected_runtime_tree=RUNTIME_TREE,
                    worker_pool_root=self.worker,
                    expected_worker_pool_sha=WORKER_SHA,
                    expected_worker_pool_tree=WORKER_TREE,
                    correlation_id="physical-preflight-003",
                    route=self.route,
                    checkout_verifier=self.verifier,
                    contract_loader=lambda _checkout: p.WorkerTransportContract(
                        FakeConfig,
                        FakeTransport,
                    ),
                    credential_runner=mutating,
                    host_verifier=lambda: None,
                )
            self.assertEqual(os.environ.get(marker), original)
        finally:
            if original is None:
                os.environ.pop(marker, None)
            else:
                os.environ[marker] = original

    def test_checkout_is_revalidated_even_when_credential_attempt_fails(self) -> None:
        calls = {"runtime": 0, "worker_pool": 0}

        def changing_verifier(
            _root: Path,
            expected_head: str,
            expected_tree: str,
            kind: str,
        ) -> p.CheckoutIdentity:
            calls[kind] += 1
            selected = p.REPOSITORY_ROOT if kind == "runtime" else self.worker
            observed_tree = (
                "9" * 40
                if kind == "runtime" and calls[kind] == 2
                else expected_tree
            )
            return p.CheckoutIdentity(selected.resolve(), expected_head, observed_tree)

        def failed_attempt(_route: credentials.S3Route, _callback: object) -> None:
            raise RuntimeError(SECRET)

        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "runtime_checkout_invalid",
        ):
            p.execute_preflight(
                expected_runtime_sha=RUNTIME_SHA,
                expected_runtime_tree=RUNTIME_TREE,
                worker_pool_root=self.worker,
                expected_worker_pool_sha=WORKER_SHA,
                expected_worker_pool_tree=WORKER_TREE,
                correlation_id="physical-preflight-failed-attempt-revalidation",
                route=self.route,
                checkout_verifier=changing_verifier,
                contract_loader=lambda _checkout: p.WorkerTransportContract(
                    FakeConfig,
                    FakeTransport,
                ),
                credential_runner=failed_attempt,
                host_verifier=lambda: None,
            )
        self.assertEqual(calls, {"runtime": 2, "worker_pool": 2})

    def test_checkout_rejects_dirty_ignored_or_special_index_state(self) -> None:
        def controlled_git(_root: Path, arguments: tuple[str, ...]) -> str:
            if arguments == ("rev-parse", "--show-toplevel"):
                return str(self.worker)
            if arguments == ("rev-parse", "--verify", "HEAD"):
                return WORKER_SHA
            if arguments == ("rev-parse", "--verify", "HEAD^{tree}"):
                return WORKER_TREE
            if arguments[0] == "status":
                return getattr(controlled_git, "status", "")
            if arguments == ("ls-files", "-v", "-z"):
                return getattr(controlled_git, "index", "H app/module.py\0")
            self.fail(f"unexpected git arguments: {arguments}")

        cases = (
            ("?? unexpected.txt\0", "H app/module.py\0"),
            ("!! app/__pycache__/module.pyc\0", "H app/module.py\0"),
            ("", "S app/module.py\0"),
            ("", "h app/module.py\0"),
            ("", ""),
        )
        for status, index in cases:
            controlled_git.status = status  # type: ignore[attr-defined]
            controlled_git.index = index  # type: ignore[attr-defined]
            with self.subTest(status=status, index=index), self.assertRaisesRegex(
                p.PhysicalPreflightError,
                "worker_pool_checkout_invalid",
            ):
                p._verify_checkout(
                    self.worker,
                    WORKER_SHA,
                    WORKER_TREE,
                    "worker_pool",
                    git_runner=controlled_git,
                )

    def test_checkout_rejects_reparse_ancestor(self) -> None:
        real_parent = self.root / "real-parent"
        real_worker = real_parent / "worker"
        real_worker.mkdir(parents=True)
        alias_parent = self.root / "alias-parent"
        try:
            alias_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink unavailable")
        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(
                alias_parent / "worker",
                WORKER_SHA,
                WORKER_TREE,
                "worker_pool",
                git_runner=lambda _root, _arguments: self.fail("git must not run"),
            )

    def test_real_git_checkout_rejects_ignored_content(self) -> None:
        repository = self.root / "real-worker"
        repository.mkdir()

        def git(*arguments: str) -> str:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=repository,
                check=True,
                text=True,
                capture_output=True,
                timeout=20,
            )
            return completed.stdout.strip()

        git("init", "--quiet")
        (repository / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (repository / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
        git("add", ".gitignore", "module.py")
        git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        head = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        self.assertEqual(p._verify_checkout(repository, head, tree, "worker_pool").head, head)
        ignored = repository / "__pycache__"
        ignored.mkdir()
        (ignored / "module.pyc").write_bytes(b"synthetic")
        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "worker_pool_checkout_invalid",
        ):
            p._verify_checkout(repository, head, tree, "worker_pool")

    def test_git_subprocess_discards_untrusted_git_environment(self) -> None:
        captured: dict[str, object] = {}

        class Done:
            returncode = 0
            stdout = "ok\n"

        def run(argv: list[str], **kwargs: object) -> Done:
            captured["argv"] = argv
            captured["environment"] = kwargs["env"]
            return Done()

        with patch.dict(
            os.environ,
            {
                "GIT_COMMON_DIR": str(self.root / "malicious"),
                "GIT_EXEC_PATH": str(self.root / "untrusted-exec"),
                "GIT_CONFIG_COUNT": "1",
            },
        ), patch.object(p.subprocess, "run", side_effect=run):
            self.assertEqual(p._git_output(self.worker, ("status",)), "ok")
        environment = captured["environment"]
        self.assertNotIn("GIT_COMMON_DIR", environment)
        self.assertNotIn("GIT_EXEC_PATH", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertIn("core.fsmonitor=false", captured["argv"])

    def test_worker_contract_must_resolve_to_verified_checkout(self) -> None:
        app = self.worker / "app"
        app.mkdir()
        module_path = app / "s3_git_bundle_artifact.py"
        native_path = app / "native_one_shot.py"
        module_path.write_text("# synthetic\n", encoding="utf-8")
        native_path.write_text("# synthetic\n", encoding="utf-8")
        synthetic = types.SimpleNamespace(
            __file__=str(module_path),
            S3ArtifactConfig=FakeConfig,
            S3GitBundleArtifactTransport=FakeTransport,
        )
        identity = p.CheckoutIdentity(self.worker, WORKER_SHA, WORKER_TREE)
        with patch.object(p.importlib, "import_module", return_value=synthetic):
            contract = p._load_worker_transport(identity)
        self.assertIs(contract.config_type, FakeConfig)
        self.assertIs(contract.transport_type, FakeTransport)

    def test_atomic_redacted_evidence_has_independent_exact_readback(self) -> None:
        evidence = self.root / "evidence" / "preflight.json"
        result = self.execute()
        p._write_evidence(
            evidence,
            result,
            additional_forbidden_roots=(self.worker,),
        )
        rendered = evidence.read_text(encoding="ascii")
        self.assertNotIn(self.route.bucket, rendered)
        self.assertNotIn(self.route.endpoint_url, rendered)
        self.assertNotIn(self.route.key_prefix, rendered)
        self.assertEqual(list(evidence.parent.glob("*.pending")), [])
        receipt = p.execute_readback(
            evidence_path=evidence,
            expected_runtime_sha=RUNTIME_SHA,
            expected_runtime_tree=RUNTIME_TREE,
            worker_pool_root=self.worker,
            expected_worker_pool_sha=WORKER_SHA,
            expected_worker_pool_tree=WORKER_TREE,
            correlation_id="physical-preflight-001",
            route=self.route,
            checkout_verifier=self.verifier,
            host_verifier=lambda: None,
        )
        self.assertEqual(
            receipt["result"],
            "NOTERI_WORKER_S3_PREFLIGHT_READBACK_PASSED",
        )
        self.assertTrue(receipt["evidence_exactly_matched"])
        self.assertFalse(receipt["storage_request_attempted"])

        value = json.loads(rendered)
        value["runtime_tree"] = "9" * 40
        evidence.write_text(
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(p.PhysicalPreflightError, "evidence_invalid"):
            p.execute_readback(
                evidence_path=evidence,
                expected_runtime_sha=RUNTIME_SHA,
                expected_runtime_tree=RUNTIME_TREE,
                worker_pool_root=self.worker,
                expected_worker_pool_sha=WORKER_SHA,
                expected_worker_pool_tree=WORKER_TREE,
                correlation_id="physical-preflight-001",
                route=self.route,
                checkout_verifier=self.verifier,
                host_verifier=lambda: None,
            )

    def test_evidence_paths_inside_either_checkout_are_rejected(self) -> None:
        for path, forbidden in (
            (p.REPOSITORY_ROOT / "forbidden-evidence.json", ()),
            (self.worker / "forbidden-evidence.json", (self.worker,)),
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                p.PhysicalPreflightError,
                "evidence_path_invalid",
            ):
                p._write_evidence(
                    path,
                    {"result": "synthetic"},
                    additional_forbidden_roots=forbidden,
                )

        real_parent = self.root / "real-evidence-parent"
        real_parent.mkdir()
        alias_parent = self.root / "alias-evidence-parent"
        try:
            alias_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError:
            return
        with self.assertRaisesRegex(
            p.PhysicalPreflightError,
            "evidence_path_invalid",
        ):
            p._write_evidence(
                alias_parent / "receipt.json",
                {"result": "synthetic"},
            )

    def test_oversized_evidence_is_rejected_before_json_decode(self) -> None:
        path = self.root / "oversized-evidence.json"
        path.write_bytes(b"x" * (p.MAX_EVIDENCE_BYTES + 1))
        with self.assertRaisesRegex(p.PhysicalPreflightError, "evidence_invalid"):
            p._read_evidence(path)

    def test_cli_failure_is_redacted_and_does_not_overwrite_evidence(self) -> None:
        output = self.root / "evidence.json"
        arguments = [
            "run",
            "--expected-runtime-sha",
            RUNTIME_SHA,
            "--expected-runtime-tree",
            RUNTIME_TREE,
            "--worker-pool-root",
            str(self.worker),
            "--expected-worker-pool-sha",
            WORKER_SHA,
            "--expected-worker-pool-tree",
            WORKER_TREE,
            "--correlation-id",
            "physical-preflight-004",
            "--bucket",
            self.route.bucket,
            "--region",
            self.route.region,
            "--endpoint-url",
            self.route.endpoint_url,
            "--key-prefix",
            self.route.key_prefix,
            "--output",
            str(output),
        ]
        stderr = io.StringIO()
        with patch.object(
            p.credentials,
            "require_windows_host",
            return_value=None,
        ), patch.object(p, "execute_preflight", side_effect=RuntimeError(SECRET)):
            with redirect_stderr(stderr):
                code = p.main(arguments)
        rendered = output.read_text(encoding="ascii") + stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn(self.route.bucket, rendered)
        self.assertNotIn(self.route.endpoint_url, rendered)
        self.assertIn("s3_preflight_failed", rendered)

        with patch.object(
            p.credentials,
            "require_windows_host",
            return_value=None,
        ), patch.object(p, "execute_preflight") as execute:
            second_code = p.main(arguments)
        self.assertEqual(second_code, 2)
        execute.assert_not_called()

    def test_cli_wrong_host_has_no_filesystem_effect(self) -> None:
        output = self.root / "must-not-exist" / "evidence.json"
        arguments = [
            "run",
            "--expected-runtime-sha",
            RUNTIME_SHA,
            "--expected-runtime-tree",
            RUNTIME_TREE,
            "--worker-pool-root",
            str(self.worker),
            "--expected-worker-pool-sha",
            WORKER_SHA,
            "--expected-worker-pool-tree",
            WORKER_TREE,
            "--correlation-id",
            "wrong-host-no-effect",
            "--bucket",
            self.route.bucket,
            "--region",
            self.route.region,
            "--endpoint-url",
            self.route.endpoint_url,
            "--key-prefix",
            self.route.key_prefix,
            "--output",
            str(output),
        ]
        stderr = io.StringIO()
        with patch.object(
            p.credentials,
            "require_windows_host",
            side_effect=credentials.CredentialBootstrapError(
                "fixed_windows_host_required",
            ),
        ), redirect_stderr(stderr):
            code = p.main(arguments)
        self.assertEqual(code, 2)
        self.assertIn("credential_operation_blocked", stderr.getvalue())
        self.assertFalse(output.parent.exists())


if __name__ == "__main__":
    unittest.main()
