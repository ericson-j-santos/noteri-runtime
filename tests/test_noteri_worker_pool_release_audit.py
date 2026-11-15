"""Tests for the pinned, read-only Noteri staged release auditor."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_release_audit as audit

ORIGIN = "https://github.com/ericson-j-santos/engineering-worker-pool"


def source_tree(root: Path) -> Path:
    source = root / "_worker_pool"
    (source / "app").mkdir(parents=True)
    (source / "contracts" / "v1").mkdir(parents=True)
    (source / "app" / "__init__.py").write_text("", encoding="utf-8")
    (source / "app" / "main.py").write_text("def main(): pass\n", encoding="utf-8")
    (source / "contracts" / "v1" / "contract.json").write_text("{}", encoding="utf-8")
    (source / "requirements.txt").write_text("fastapi==0.115.0\n", encoding="utf-8")
    return source


def prepare(tmp_path: Path):
    source = source_tree(tmp_path)
    releases = tmp_path / "releases"
    stage.stage(source=source, releases=releases,
                expected_sha=audit.SOURCE_SHA, profile="NORMAL", hostname="Noteri",
                platform="nt",
                inspect_git=lambda _: (audit.SOURCE_SHA, ORIGIN, ""), dry_run=False)
    return source, releases / audit.SOURCE_SHA


def check(source, release, **extra):
    return audit.audit(source=source, release=release, profile="NORMAL",
                       hostname="Noteri", platform="nt",
                       inspect_git=lambda _: (audit.SOURCE_SHA, ORIGIN, ""), **extra)


def snapshot(release: Path):
    return {x.relative_to(release).as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
            for x in release.rglob("*") if x.is_file() and not x.is_symlink()}


def test_intact_manifest_and_all_files_are_read_only(tmp_path):
    source, release = prepare(tmp_path)
    before = snapshot(release)
    result = check(source, release)
    assert result["result"] == "RELEASE_INTACT"
    assert result["source_identity_verified"] is True
    assert result["expected_file_count"] == 4
    assert not any(result["counts"].values())
    assert result["state_changed"] is False
    assert result["secrets_read"] is False
    assert result["activated"] is False
    assert result["execution_authorized"] is False
    assert before == snapshot(release)


def test_single_hash_mismatch_reports_name_and_digests(tmp_path):
    source, release = prepare(tmp_path)
    path = release / "app" / "main.py"
    path.write_text("tampered\n", encoding="utf-8")
    before = snapshot(release)
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert result["counts"]["hash_mismatch"] == 1
    assert result["hash_mismatch"] == [{
        "path": "app/main.py",
        "expected_sha256": stage.file_sha256(source / "app" / "main.py"),
        "observed_sha256": stage.file_sha256(path),
    }]
    assert before == snapshot(release)


def test_missing_file_does_not_trigger_repair(tmp_path):
    source, release = prepare(tmp_path)
    (release / "contracts" / "v1" / "contract.json").unlink()
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert result["missing"] == ["contracts/v1/contract.json"]
    assert result["counts"]["missing"] == 1
    assert not (release / "contracts" / "v1" / "contract.json").exists()


def test_extra_safe_file_is_reported_by_relative_path_only(tmp_path):
    source, release = prepare(tmp_path)
    (release / "app" / "unexpected.py").write_text("extra\n", encoding="utf-8")
    result = check(source, release)
    assert result["counts"]["extra"] == 1
    assert result["extra"] == ["app/unexpected.py"]
    assert result["result"] == "RELEASE_MISMATCH"


def test_unknown_sensitive_extra_file_is_fingerprinted_without_reading(tmp_path, monkeypatch):
    source, release = prepare(tmp_path)
    secret = release / "api-token.txt"
    secret.write_text("fixture-confidential-byte-content", encoding="utf-8")
    original = Path.read_bytes

    def guarded_read(path):
        if str(path) == str(secret):
            raise AssertionError("Unknown extra file content was read")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    result = check(source, release)
    serialized = json.dumps(result)
    assert result["counts"]["extra"] == 1
    assert result["extra"][0].startswith("redacted:")
    assert "api-token.txt" not in serialized
    assert "fixture-confidential" not in serialized
    assert result["secrets_read"] is False


def test_bad_manifest_metadata_and_hash_are_classified(tmp_path):
    source, release = prepare(tmp_path)
    manifest = release / "manifest.json"
    changed = json.loads(manifest.read_text(encoding="utf-8"))
    changed["source_repo"] = "other/repository"
    changed["files"]["app/main.py"] = "f" * 64
    manifest.write_text(json.dumps(changed), encoding="utf-8")
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert result["installed_manifest"] == "valid"
    assert "source_repo" in result["manifest_metadata_mismatch"]
    assert result["manifest_hash_mismatch"] == ["app/main.py"]
    assert result["counts"]["hash_mismatch"] == 0


def test_missing_manifest_reports_without_creating_it(tmp_path):
    source, release = prepare(tmp_path)
    manifest = release / "manifest.json"
    manifest.unlink()
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert result["installed_manifest"] == "missing"
    assert not manifest.exists()


@pytest.mark.parametrize("profile,hostname,platform", [
    ("ESTUDO", "Noteri", "nt"), ("NORMAL", "Desktop", "nt"),
    ("NORMAL", "Noteri", "posix"),
])
def test_wrong_host_or_profile_never_reads_release(tmp_path, monkeypatch,
                                                   profile, hostname, platform):
    source, release = prepare(tmp_path)
    monkeypatch.setattr(audit, "_inventory",
                        lambda *_: pytest.fail("Release should not be inspected"))
    r = audit.audit(source=source, release=release, profile=profile,
                    hostname=hostname, platform=platform)
    assert r["result"] == "BLOCKED_HOST_PROFILE"


@pytest.mark.parametrize("sha,remote,dirty", [
    ("a" * 40, ORIGIN, ""),
    (audit.SOURCE_SHA, "https://github.com/attacker/repository", ""),
    (audit.SOURCE_SHA, ORIGIN, " M app/main.py"),
])
def test_source_identity_drifts_fail_closed(tmp_path, monkeypatch, sha, remote, dirty):
    source, release = prepare(tmp_path)
    monkeypatch.setattr(audit, "_inventory",
                        lambda *_: pytest.fail("Untrusted source allowed"))
    r = audit.audit(source=source, release=release, profile="NORMAL",
                    hostname="Noteri", platform="nt",
                    inspect_git=lambda _: (sha, remote, dirty))
    assert r["result"] == "BLOCKED_SOURCE_IDENTITY"


def test_release_symlink_is_not_followed(tmp_path):
    source, release = prepare(tmp_path)
    (release / "app" / "main.py").unlink()
    try:
        (release / "app" / "main.py").symlink_to(tmp_path / "_worker_pool" /
                                                "app" / "main.py")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink requires platform privilege")
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert "app/main.py" in result["unsafe_entries"]
    assert "app/main.py" in result["missing"]


def test_manifest_link_fails_closed(tmp_path):
    source, release = prepare(tmp_path)
    manifest = release / "manifest.json"
    manifest.unlink()
    try:
        manifest.symlink_to(source / "requirements.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink requires platform privilege")
    result = check(source, release)
    assert result["installed_manifest"] == "unsafe"
    assert result["result"] == "RELEASE_MISMATCH"


def test_no_arbitrary_user_paths_or_mutating_surface():
    src = (Path(__file__).resolve().parents[1] /
           "scripts" / "noteri_worker_pool_release_audit.py").read_text(encoding="utf-8")
    assert "argparse" not in src
    assert "sys.argv" not in src
    assert "subprocess.run" not in src
    assert "subprocess.Popen" not in src
    assert "shutil.rmtree" not in src
    assert ".write_text(" not in src
    assert ".unlink(" not in src
    assert "os.remove(" not in src
    assert "token_file" not in src


def test_known_python_bytecode_cache_is_named_without_reading_bytes(tmp_path, monkeypatch):
    """The observed Noteri fingerprint maps to a safe, exact relative name."""
    source, release = prepare(tmp_path)
    entry = release / "app" / "__pycache__" / "secure_file.cpython-314.pyc"
    entry.parent.mkdir()
    entry.write_bytes(b"synthetic bytecode fixture; not an executable module")
    assert hashlib.sha256(entry.relative_to(release).as_posix().encode()).hexdigest()[:16] == (
        "2795a17de0a305f8")
    original = Path.read_bytes

    def no_cache_reads(path):
        if str(path) == str(entry):
            raise AssertionError("Audit must not open an unknown cache file")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", no_cache_reads)
    result = check(source, release)
    assert result["result"] == "RELEASE_MISMATCH"
    assert result["extra"] == ["app/__pycache__/secure_file.cpython-314.pyc"]
    assert result["counts"]["extra"] == 1
    assert result["counts"]["hash_mismatch"] == 0
    assert result["state_changed"] is False
    assert result["secrets_read"] is False
