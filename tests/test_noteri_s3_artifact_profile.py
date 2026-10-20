import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_s3_artifact_profile.py"
SPEC = importlib.util.spec_from_file_location("noteri_s3_profile", SOURCE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_contract_is_pinned_to_reviewed_worker_profile() -> None:
    assert m.WORKER_SHA == "5ef413c1c18996bd022c20987fb75dbb9ec47712"
    assert m.RULES_SHA == "a430688c499077f5472841560f224c40766b0b78"
    assert m.REQUIREMENTS_BYTES == b"boto3==1.43.115\n"
    assert m.REQUIREMENTS_URL.startswith("https://raw.githubusercontent.com/")
    assert m.WORKER_SHA in m.REQUIREMENTS_URL


def test_pip_is_binary_only_and_import_is_isolated(tmp_path: Path) -> None:
    repo = tmp_path / "chatgpt-workers" / "wt-session"
    repo.mkdir(parents=True)
    output = repo / "evidence" / "noteri-s3-artifact-profile" / "proof.json"
    calls = []

    def fake_git(_repo, *arguments):
        return "a" * 40 if arguments == ("rev-parse", "HEAD") else ""

    def runner(command, *, cwd, timeout, env=None):
        calls.append((command, env or {}))
        if "probe-import" in command:
            return completed(stdout=json.dumps({
                "boto3_version": "1.43.115",
                "botocore_version": "1.43.115",
                "modules_loaded_from_isolated_root": True,
                "native_extension_count": 0,
                "s3_client_created": False,
                "storage_request_attempted": False,
                "credential_input_requested": False,
            }))
        return completed()

    with patch.object(m, "require_noteri"), patch.object(
        m, "git", side_effect=fake_git
    ):
        result = m.qualify(
            repo=repo,
            output=output,
            expected_runtime_sha="a" * 40,
            rules_sha=m.RULES_SHA,
            correlation_id="profile-test-1",
            downloader=lambda: m.REQUIREMENTS_BYTES,
            runner=runner,
            asset_root=tmp_path / "chatgpt-workers" / "runtime-assets",
        )

    install = calls[0][0]
    assert install[1:3] == ["-I", "-B"]
    assert "--isolated" in install
    assert "--only-binary=:all:" in install
    assert "--no-input" in install
    assert "--no-compile" in install
    assert "--no-cache-dir" in install
    assert "--keyring-provider=disabled" in install
    assert "https://pypi.org/simple" in install
    assert calls[1][0][1:3] == ["-I", "-B"]
    assert all(not key.startswith("AWS_") for key in calls[0][1])
    assert "PYTHONPATH" not in calls[0][1]
    assert calls[0][1]["PIP_CONFIG_FILE"] == m.os.devnull
    assert result["transport_ready"] is False
    assert result["pip_configuration_disabled"] is True
    assert result["package_cache_used"] is False
    assert result["temporary_environment_removed"] is True
    assert list((tmp_path / "chatgpt-workers" / "runtime-assets").iterdir()) == []
    assert json.loads(output.read_text(encoding="ascii")) == result
    assert str(tmp_path) not in output.read_text(encoding="ascii")


def test_source_drift_blocks_before_dependency_process(tmp_path: Path) -> None:
    repo = tmp_path / "chatgpt-workers" / "wt-session"
    repo.mkdir(parents=True)
    with patch.object(m, "require_noteri"), patch.object(
        m, "git", return_value="b" * 40
    ):
        with pytest.raises(m.Blocked, match="runtime_sha_mismatch"):
            m.qualify(
                repo=repo,
                output=repo / "evidence" / "noteri-s3-artifact-profile" / "proof.json",
                expected_runtime_sha="a" * 40,
                rules_sha=m.RULES_SHA,
                correlation_id="profile-test-2",
                runner=lambda *args, **kwargs: pytest.fail("runner must not execute"),
                asset_root=tmp_path / "chatgpt-workers" / "runtime-assets",
            )


def test_asset_root_inside_git_blocks_before_dependency_process(tmp_path: Path) -> None:
    repo = tmp_path / "chatgpt-workers" / "wt-session"
    repo.mkdir(parents=True)
    assets = tmp_path / "asset-repository" / "runtime-assets"
    assets.mkdir(parents=True)
    (assets.parent / ".git").mkdir()

    def fake_git(_repo, *arguments):
        return "a" * 40 if arguments == ("rev-parse", "HEAD") else ""

    with patch.object(m, "require_noteri"), patch.object(
        m, "git", side_effect=fake_git
    ):
        with pytest.raises(m.Blocked, match="asset_root_inside_git"):
            m.qualify(
                repo=repo,
                output=repo / "evidence" / "noteri-s3-artifact-profile" / "proof.json",
                expected_runtime_sha="a" * 40,
                rules_sha=m.RULES_SHA,
                correlation_id="profile-test-git-root",
                runner=lambda *args, **kwargs: pytest.fail("runner must not execute"),
                asset_root=assets,
            )


def test_wrong_host_and_rules_fail_closed(tmp_path: Path) -> None:
    repo = tmp_path / "chatgpt-workers" / "wt-session"
    repo.mkdir(parents=True)
    with patch.object(
        m, "require_noteri", side_effect=m.Blocked("noteri_host_required")
    ):
        with pytest.raises(m.Blocked, match="noteri_host_required"):
            m.qualify(
                repo=repo,
                output=Path("evidence/noteri-s3-artifact-profile/proof.json"),
                expected_runtime_sha="a" * 40,
                rules_sha=m.RULES_SHA,
                correlation_id="profile-test-3",
            )
    with patch.object(m, "require_noteri"):
        with pytest.raises(m.Blocked, match="rules_sha_unapproved"):
            m.qualify(
                repo=repo,
                output=Path("evidence/noteri-s3-artifact-profile/proof.json"),
                expected_runtime_sha="a" * 40,
                rules_sha="b" * 40,
                correlation_id="profile-test-3",
            )


def test_import_probe_rejects_native_extension_before_import(tmp_path: Path) -> None:
    (tmp_path / "unexpected.pyd").write_bytes(b"native")
    with pytest.raises(m.Blocked, match="native_dependency_detected"):
        m.probe_import(tmp_path)


def test_readback_detects_residual_environment_and_tamper(tmp_path: Path) -> None:
    repo = tmp_path / "chatgpt-workers" / "wt-session"
    repo.mkdir(parents=True)
    assets = tmp_path / "chatgpt-workers" / "runtime-assets"
    assets.mkdir()
    output = repo / "evidence" / "noteri-s3-artifact-profile" / "proof.json"
    output.parent.mkdir(parents=True)
    evidence = m.success_evidence(
        "a" * 40,
        m.RULES_SHA,
        "profile-test-4",
        "noteri-s3-artifact-residual",
        {"boto3_version": "1.43.115", "botocore_version": "1.43.115"},
    )
    output.write_text(json.dumps(evidence), encoding="ascii")
    (assets / evidence["environment_name"]).mkdir()

    def fake_git(_repo, *arguments):
        return "a" * 40 if arguments == ("rev-parse", "HEAD") else ""

    with patch.object(m, "require_noteri"), patch.object(
        m, "git", side_effect=fake_git
    ):
        with pytest.raises(m.Blocked, match="temporary_environment_still_present"):
            m.readback(
                repo=repo, output=output, expected_runtime_sha="a" * 40,
                rules_sha=m.RULES_SHA, correlation_id="profile-test-4", asset_root=assets,
            )
        (assets / evidence["environment_name"]).rmdir()
        evidence["transport_ready"] = True
        output.write_text(json.dumps(evidence), encoding="ascii")
        with pytest.raises(m.Blocked, match="evidence_transport_ready_mismatch"):
            m.readback(
                repo=repo, output=output, expected_runtime_sha="a" * 40,
                rules_sha=m.RULES_SHA, correlation_id="profile-test-4", asset_root=assets,
            )


def test_blocked_evidence_never_echoes_untrusted_error() -> None:
    payload = m.blocked_evidence("not-a-sha", "bad", "bad/id", "secret value")
    assert "secret value" not in json.dumps(payload)
    assert payload["code"] == "qualification_failed"
    assert payload["transport_ready"] is False


def test_requirements_hash_is_stable() -> None:
    assert len(hashlib.sha256(m.REQUIREMENTS_BYTES).hexdigest()) == 64


def gateway_bundle_fixture(tmp_path: Path) -> Path:
    root = tmp_path / m.GATEWAY_BUNDLE_NAME
    payloads = {
        "bin/command_gateway.py": b"gateway",
        "bin/session_launcher.py": b"launcher",
        "config/policy.json": b"{}",
    }
    files = {}
    for relative, payload in payloads.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        files[relative] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    manifest = {
        "schema_version": m.GATEWAY_BUNDLE_SCHEMA,
        "repository": m.REPOSITORY,
        "runtime_sha": "a" * 40,
        "rules_sha": m.RULES_SHA,
        "rules_version": m.RULES_VERSION,
        "run_id": 10,
        "run_attempt": 1,
        "files": files,
    }
    (root / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="ascii")
    return root


def test_gateway_manifest_contract_matches_embedded_files(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    entries = [
        {"path": source, "sha256": m.GATEWAY_FILES[destination][0],
         "size": m.GATEWAY_FILES[destination][1]}
        for source, destination in m.GATEWAY_SOURCE_MAP.items()
    ]
    manifest = {"version": m.RULES_VERSION, "files": entries}
    (rules / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")

    def fake_git(_repo, *arguments):
        return m.RULES_SHA if arguments == ("rev-parse", "HEAD") else ""

    with patch.object(m, "git", side_effect=fake_git):
        result = m.verify_gateway_contract(rules)
        assert result["managed_file_count"] == len(m.GATEWAY_FILES)
        manifest["files"][0]["sha256"] = "0" * 64
        (rules / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(m.Blocked, match="gateway_manifest_file_mismatch"):
            m.verify_gateway_contract(rules)


def test_gateway_bundle_accepts_only_exact_binding_and_bytes(tmp_path: Path) -> None:
    root = gateway_bundle_fixture(tmp_path)
    expected = {
        relative: (metadata["sha256"], metadata["size"])
        for relative, metadata in json.loads(
            (root / "bundle-manifest.json").read_text(encoding="ascii")
        )["files"].items()
    }
    with patch.object(m, "GATEWAY_FILES", expected):
        _, gateway, launcher, policy = m.validate_gateway_bundle(
            root, m.RULES_SHA, "a" * 40, "10", "1"
        )
        assert gateway == root / "bin" / "command_gateway.py"
        assert launcher == root / "bin" / "session_launcher.py"
        assert policy == root / "config" / "policy.json"
        (root / "extra.py").write_text("unexpected", encoding="utf-8")
        with pytest.raises(m.Blocked, match="gateway_bundle_file_set_invalid"):
            m.validate_gateway_bundle(root, m.RULES_SHA, "a" * 40, "10", "1")
        (root / "extra.py").unlink()
        gateway.write_bytes(b"tampered")
        with pytest.raises(m.Blocked, match="gateway_file_invalid|gateway_file_hash_mismatch"):
            m.validate_gateway_bundle(root, m.RULES_SHA, "a" * 40, "10", "1")


def test_gateway_bundle_rejects_stale_run_binding(tmp_path: Path) -> None:
    root = gateway_bundle_fixture(tmp_path)
    manifest_path = root / "bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    expected = {
        relative: (metadata["sha256"], metadata["size"])
        for relative, metadata in manifest["files"].items()
    }
    manifest["run_id"] = 9
    manifest_path.write_text(json.dumps(manifest), encoding="ascii")
    with patch.object(m, "GATEWAY_FILES", expected):
        with pytest.raises(m.Blocked, match="gateway_bundle_binding_mismatch"):
            m.validate_gateway_bundle(root, m.RULES_SHA, "a" * 40, "10", "1")


def test_gateway_bundle_rejects_symlink(tmp_path: Path) -> None:
    root = gateway_bundle_fixture(tmp_path)
    expected = {
        relative: (metadata["sha256"], metadata["size"])
        for relative, metadata in json.loads(
            (root / "bundle-manifest.json").read_text(encoding="ascii")
        )["files"].items()
    }
    (root / "linked.py").symlink_to(root / "bin" / "command_gateway.py")
    with patch.object(m, "GATEWAY_FILES", expected):
        with pytest.raises(m.Blocked, match="reparse_path_rejected"):
            m.validate_gateway_bundle(root, m.RULES_SHA, "a" * 40, "10", "1")


def test_build_gateway_bundle_binds_current_run(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    source_map = {
        "scripts/command_gateway.py": "bin/command_gateway.py",
        "scripts/session_launcher.py": "bin/session_launcher.py",
        "config/command-gateway.policy.json": "config/policy.json",
    }
    files = {}
    entries = []
    for index, (source, destination) in enumerate(source_map.items()):
        raw = f"payload-{index}".encode("ascii")
        path = rules.joinpath(*source.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        files[destination] = (digest, len(raw))
        entries.append({"path": source, "sha256": digest, "size": len(raw)})
    (rules / "MANIFEST.json").write_text(
        json.dumps({"version": m.RULES_VERSION, "files": entries}), encoding="utf-8"
    )
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": m.REPOSITORY,
        "GITHUB_ACTOR": m.OWNER,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF_NAME": "feat/noteri-s3-artifact-test",
        "GITHUB_RUN_ID": "10",
        "GITHUB_RUN_ATTEMPT": "1",
    }

    def fake_git(_repo, *arguments):
        return m.RULES_SHA if arguments == ("rev-parse", "HEAD") else ""

    output = tmp_path / m.GATEWAY_BUNDLE_NAME
    with patch.object(m, "GATEWAY_SOURCE_MAP", source_map), patch.object(
        m, "GATEWAY_FILES", files
    ), patch.object(m, "git", side_effect=fake_git), patch.dict(
        m.os.environ, environment, clear=True
    ):
        result = m.build_gateway_bundle(rules, output)
        assert result["result"] == "TRANSIENT_GATEWAY_BUNDLE_BUILT"
        m.validate_gateway_bundle(output, m.RULES_SHA, "a" * 40, "10", "1")


def test_actions_context_rejects_pr_and_non_owner() -> None:
    base = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": m.REPOSITORY,
        "GITHUB_ACTOR": m.OWNER,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_REF_NAME": "feat/noteri-s3-artifact-test",
        "GITHUB_RUN_ID": "10",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    with patch.dict(m.os.environ, base, clear=True):
        assert m.actions_context() == (
            "a" * 40,
            "feat/noteri-s3-artifact-test",
            "10",
            "1",
        )
        m.os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        with pytest.raises(m.Blocked, match="event_not_authorized"):
            m.actions_context()
        m.os.environ["GITHUB_EVENT_NAME"] = "push"
        m.os.environ["GITHUB_ACTOR"] = "fork-user"
        with pytest.raises(m.Blocked, match="actor_not_authorized"):
            m.actions_context()
