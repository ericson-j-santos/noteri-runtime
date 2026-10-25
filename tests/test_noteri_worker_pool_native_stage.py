from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_native_stage as stage

SHA = "a" * 40
ORIGIN = "https://github.com/ericson-j-santos/engineering-worker-pool"


def source_tree(root: Path) -> Path:
    repo = root / "_worker_pool"
    (repo / "app").mkdir(parents=True)
    (repo / "contracts" / "v1").mkdir(parents=True)
    (repo / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    (repo / "app" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "app" / "main.py").write_text("def health(): return True\n", encoding="utf-8")
    (repo / "contracts" / "v1" / "contract.json").write_text(
        '{"contract_version":"v1"}\n', encoding="utf-8"
    )
    return repo


def invoke(repo: Path, root: Path, **overrides):
    options = {
        "source": repo,
        "releases": root / "releases",
        "expected_sha": SHA,
        "profile": "NORMAL",
        "hostname": "Noteri",
        "platform": "nt",
        "inspect_git": lambda _: (SHA, ORIGIN, ""),
    }
    options.update(overrides)
    return stage.stage(**options)


def test_readonly_plan_never_materializes_runtime(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    result = invoke(repo, tmp_path)
    assert result["result"] == "STAGE_PLAN_READY"
    assert not (tmp_path / "releases").exists()
    assert result["activated"] is False
    assert result["secrets_read"] is False
    assert result["state_changed"] is False


def test_staged_release_has_digest_manifest_and_idempotent_replay(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    first = invoke(repo, tmp_path, dry_run=False)
    assert first["result"] == "STAGED_ONLY"
    assert first["state_changed"] is True
    assert first["activated"] is False
    target = tmp_path / "releases" / SHA
    assert (target / "app" / "main.py").read_bytes() == (repo / "app" / "main.py").read_bytes()
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_sha"] == SHA
    assert manifest["source_repo"] == stage.EXPECTED_REPO
    assert manifest["activated"] is False
    assert set(manifest["files"]) == {
        "requirements.txt", "app/main.py", "app/__init__.py", "contracts/v1/contract.json"
    }
    assert stage.validate_staged(target, manifest)
    again = invoke(repo, tmp_path, dry_run=False)
    assert again["result"] == "ALREADY_STAGED"
    assert again["state_changed"] is False
    assert not (tmp_path / "releases" / ".stage.lock").exists()
    assert list((tmp_path / "releases").iterdir()) == [target]


@pytest.mark.parametrize(
    "reason,override",
    [
        ("host_not_allowed", {"hostname": "DESKTOP-PDQK954"}),
        ("host_not_allowed", {"platform": "posix"}),
        ("profile_not_normal", {"profile": "ESTUDO"}),
        ("source_sha_invalid", {"expected_sha": "bad"}),
        ("activation_not_supported", {"activate": True}),
    ],
)
def test_context_and_activation_are_denied_before_writes(
    tmp_path: Path, reason: str, override: dict
) -> None:
    repo = source_tree(tmp_path)
    with pytest.raises(stage.StageBlocked, match=reason):
        invoke(repo, tmp_path, dry_run=False, **override)
    assert not (tmp_path / "releases").exists()


@pytest.mark.parametrize(
    "inspector",
    [
        lambda _: ("b" * 40, ORIGIN, ""),
        lambda _: (SHA, "https://github.com/untrusted/repo", ""),
        lambda _: (SHA, ORIGIN, " M app/main.py"),
    ],
)
def test_sha_remote_and_clean_tree_are_required(
    tmp_path: Path, inspector
) -> None:
    repo = source_tree(tmp_path)
    with pytest.raises(stage.StageBlocked, match="source_identity_unverified"):
        invoke(repo, tmp_path, dry_run=False, inspect_git=inspector)
    assert not (tmp_path / "releases").exists()


def test_missing_required_contract_blocks_without_staging(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    (repo / "contracts" / "v1" / "contract.json").unlink()
    with pytest.raises(stage.StageBlocked, match="source_contract_missing"):
        invoke(repo, tmp_path, dry_run=False)
    assert not (tmp_path / "releases").exists()


def test_unexpected_file_extension_blocks_without_staging(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    (repo / "app" / "secret.pem").write_text("not a secret", encoding="utf-8")
    with pytest.raises(stage.StageBlocked, match="source_extension_unexpected"):
        invoke(repo, tmp_path, dry_run=False)
    assert not (tmp_path / "releases").exists()


def test_source_symlink_blocks_before_mutation(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    (repo / "app" / "alias.py").symlink_to(repo / "app" / "main.py")
    with pytest.raises(stage.StageBlocked, match="source_link_forbidden"):
        invoke(repo, tmp_path, dry_run=False)
    assert not (tmp_path / "releases").exists()


def test_existing_stage_must_have_same_content(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    invoke(repo, tmp_path, dry_run=False)
    target = tmp_path / "releases" / SHA / "app" / "main.py"
    target.write_text("tampered", encoding="utf-8")
    with pytest.raises(stage.StageBlocked, match="existing_release_integrity_mismatch"):
        invoke(repo, tmp_path, dry_run=False)
    assert target.read_text(encoding="utf-8") == "tampered"


def test_existing_symlink_blocks_before_read(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    releases = tmp_path / "releases"
    releases.mkdir()
    (releases / SHA).symlink_to(repo, target_is_directory=True)
    with pytest.raises(stage.StageBlocked, match="release_link_forbidden"):
        invoke(repo, tmp_path, dry_run=False)


def test_lock_collision_fails_closed_without_overwrite(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    releases = tmp_path / "releases"
    releases.mkdir()
    (releases / ".stage.lock").write_text("other writer", encoding="utf-8")
    with pytest.raises(stage.StageBlocked, match="stage_lock_busy"):
        invoke(repo, tmp_path, dry_run=False)
    assert (releases / ".stage.lock").read_text(encoding="utf-8") == "other writer"
    assert not (releases / SHA).exists()


def test_manifest_and_stage_include_no_secret_or_active_pointer(tmp_path: Path) -> None:
    repo = source_tree(tmp_path)
    invoke(repo, tmp_path, dry_run=False)
    target = tmp_path / "releases" / SHA
    data = (target / "manifest.json").read_text(encoding="utf-8")
    assert "token" not in data.lower()
    assert "password" not in data.lower()
    assert not (tmp_path / "active.json").exists()
    assert not (tmp_path / "releases" / "active.json").exists()


def test_source_does_not_install_start_or_rotate_credentials() -> None:
    raw = (Path(__file__).resolve().parents[1] / "scripts/noteri_worker_pool_native_stage.py").read_text(
        encoding="utf-8"
    ).lower()
    assert "docker " not in raw
    assert "uvicorn " not in raw
    assert "schtasks " not in raw
    assert "subprocess.popen" not in raw
    assert "token_urlsafe" not in raw
