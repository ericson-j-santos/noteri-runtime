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


def test_rules_checkout_rejects_tracked_drift(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    (rules / "scripts").mkdir(parents=True)
    (rules / "config").mkdir()
    (rules / "scripts" / "command_gateway.py").write_text("", encoding="utf-8")
    (rules / "scripts" / "session_launcher.py").write_text("", encoding="utf-8")
    (rules / "config" / "command-gateway.policy.json").write_text("{}", encoding="utf-8")

    def fake_git(_repo, *arguments):
        if arguments == ("rev-parse", "HEAD"):
            return m.RULES_SHA
        return " M scripts/command_gateway.py"

    with patch.object(m, "git", side_effect=fake_git):
        with pytest.raises(m.Blocked, match="rules_checkout_dirty"):
            m.validate_rules_checkout(rules, m.RULES_SHA)


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
