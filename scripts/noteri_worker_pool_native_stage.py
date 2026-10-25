#!/usr/bin/env python3
"""Prepare an immutable Noteri-local Worker Pool release without activating it.

Never installs packages, starts a process, schedules a task or reads credentials.
Run only through an approved Session Launcher / Command Gateway on Noteri.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

EXPECTED_REPO = "ericson-j-santos/engineering-worker-pool"
EXPECTED_HOST = "noteri"
EXPECTED_CONTEXT_REPO = "ericson-j-santos/noteri-runtime"
CONFIRM = "STAGE-NOTERI-WORKER-POOL"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SUFFIXES = {".py", ".sql", ".json", ".md"}
MAX_FILES = 800
MAX_FILE_SIZE = 4 * 1024 * 1024
MAX_TOTAL_SIZE = 35 * 1024 * 1024
REQUIRED = frozenset(("requirements.txt", "app/__init__.py", "app/main.py", "contracts/v1/contract.json"))
ORIGINS = frozenset((
    f"https://github.com/{EXPECTED_REPO}",
    f"https://github.com/{EXPECTED_REPO}.git",
    f"git@github.com:{EXPECTED_REPO}.git",
))


class StageBlocked(RuntimeError):
    pass


def is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def git_read(source: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args], capture_output=True,
            encoding="utf-8", errors="replace", timeout=15, check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise StageBlocked("source_git_unavailable") from exc
    return result.stdout.strip()


def git_identity(source: Path) -> tuple[str, str, str]:
    return (
        git_read(source, "rev-parse", "HEAD"),
        git_read(source, "remote", "get-url", "origin"),
        git_read(source, "status", "--porcelain", "--untracked-files=no"),
    )


def safe_source_files(source: Path) -> dict[str, Path]:
    if is_link(source) or not source.is_dir():
        raise StageBlocked("source_invalid")
    result: dict[str, Path] = {}
    for relative_root in ("app", "contracts/v1"):
        directory = source / relative_root
        if not directory.is_dir() or is_link(directory):
            raise StageBlocked("source_tree_invalid")
        for item in directory.rglob("*"):
            if is_link(item):
                raise StageBlocked("source_link_forbidden")
            if item.is_dir():
                continue
            if not item.is_file():
                raise StageBlocked("source_unexpected_type")
            name = item.relative_to(source).as_posix()
            if item.suffix not in SUFFIXES or item.name.startswith("."):
                raise StageBlocked("source_extension_unexpected")
            result[name] = item
    requirements = source / "requirements.txt"
    if is_link(requirements) or not requirements.is_file():
        raise StageBlocked("source_requirements_missing")
    result["requirements.txt"] = requirements
    if not REQUIRED.issubset(result):
        raise StageBlocked("source_contract_missing")
    if len(result) > MAX_FILES:
        raise StageBlocked("source_too_many_files")
    total = 0
    for item in result.values():
        size = item.stat().st_size
        if size > MAX_FILE_SIZE:
            raise StageBlocked("source_file_too_large")
        total += size
        if total > MAX_TOTAL_SIZE:
            raise StageBlocked("source_too_large")
    return dict(sorted(result.items()))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(source_sha: str, files: dict[str, Path]) -> dict:
    return {
        "schema_version": "1",
        "kind": "noteri_worker_pool_stage_only",
        "source_sha": source_sha,
        "source_repo": EXPECTED_REPO,
        "activated": False,
        "files": {relative: file_sha256(path) for relative, path in files.items()},
    }


def validate_staged(release: Path, manifest: dict) -> bool:
    if is_link(release) or not release.is_dir():
        return False
    current = release / "manifest.json"
    if is_link(current) or not current.is_file():
        return False
    try:
        existing = json.loads(current.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if existing != manifest:
        return False
    expected = set(manifest["files"])
    observed: set[str] = set()
    for path in release.rglob("*"):
        if is_link(path):
            return False
        if not path.is_file():
            continue
        relative = path.relative_to(release).as_posix()
        if relative != "manifest.json":
            observed.add(relative)
    if observed != expected:
        return False
    return all(
        (release / path).is_file() and file_sha256(release / path) == digest
        for path, digest in manifest["files"].items()
    )


def stage(
    *,
    source: Path,
    releases: Path,
    expected_sha: str,
    profile: str,
    hostname: str,
    platform: str,
    inspect_git: Callable[[Path], tuple[str, str, str]] = git_identity,
    activate: bool = False,
    dry_run: bool = True,
) -> dict:
    if activate:
        raise StageBlocked("activation_not_supported")
    if platform != "nt" or hostname.casefold() != EXPECTED_HOST:
        raise StageBlocked("host_not_allowed")
    if profile != "NORMAL":
        raise StageBlocked("profile_not_normal")
    if not SHA40.fullmatch(expected_sha):
        raise StageBlocked("source_sha_invalid")
    observed_sha, origin, dirty = inspect_git(source)
    if observed_sha != expected_sha or origin not in ORIGINS or dirty:
        raise StageBlocked("source_identity_unverified")
    files = safe_source_files(source)
    manifest = build_manifest(expected_sha, files)
    release = releases / expected_sha
    if is_link(releases) or is_link(release):
        raise StageBlocked("release_link_forbidden")
    if release.exists():
        if not validate_staged(release, manifest):
            raise StageBlocked("existing_release_integrity_mismatch")
        return {
            "result": "ALREADY_STAGED", "source_sha": expected_sha,
            "file_count": len(files), "state_changed": False,
            "activated": False, "secrets_read": False,
        }
    if dry_run:
        return {
            "result": "STAGE_PLAN_READY", "source_sha": expected_sha,
            "file_count": len(files), "state_changed": False,
            "activated": False, "secrets_read": False,
        }

    releases.mkdir(parents=True, exist_ok=True)
    lock = releases / ".stage.lock"
    try:
        handle = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise StageBlocked("stage_lock_busy") from exc
    except OSError as exc:
        raise StageBlocked("stage_lock_unavailable") from exc
    os.close(handle)
    temporary: Path | None = None
    try:
        if release.exists():
            raise StageBlocked("concurrent_release_present")
        temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=releases))
        for relative, origin_path in files.items():
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin_path, target)
            if file_sha256(target) != manifest["files"][relative]:
                raise StageBlocked("stage_copy_integrity_failed")
        (temporary / "manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        if not validate_staged(temporary, manifest):
            raise StageBlocked("stage_manifest_invalid")
        if release.exists():
            raise StageBlocked("concurrent_release_present")
        os.rename(temporary, release)
        temporary = None
        return {
            "result": "STAGED_ONLY", "source_sha": expected_sha,
            "file_count": len(files), "state_changed": True,
            "activated": False, "secrets_read": False,
        }
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
        lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--mode", choices=("plan", "stage"), default="plan")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        env = os.environ
        if (
            env.get("GITHUB_ACTIONS") != "true"
            or env.get("GITHUB_REPOSITORY") != EXPECTED_CONTEXT_REPO
            or env.get("GITHUB_REF") != "refs/heads/main"
            or not env.get("GITHUB_WORKSPACE")
            or not env.get("LOCALAPPDATA")
        ):
            raise StageBlocked("trusted_execution_context_missing")
        if args.mode == "stage" and args.confirm != CONFIRM:
            raise StageBlocked("stage_confirmation_missing")
        workspace = Path(env["GITHUB_WORKSPACE"])
        source = workspace / "_worker_pool"
        profile_file = Path(env["LOCALAPPDATA"]) / "ReqSys" / "TodoGlobal24x7" / "host-profile.json"
        try:
            profile = json.loads(profile_file.read_text(encoding="utf-8")).get("profile")
        except (OSError, ValueError):
            raise StageBlocked("profile_unavailable") from None
        releases = Path(env["LOCALAPPDATA"]) / "ReqSys" / "NoteriWorkerPool" / "releases"
        result = stage(
            source=source, releases=releases, expected_sha=args.source_sha,
            profile=profile, hostname=socket.gethostname(), platform=os.name,
            dry_run=args.mode != "stage",
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except StageBlocked as exc:
        print(json.dumps({"result": "STAGE_BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
