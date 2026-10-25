#!/usr/bin/env python3
"""Prepare an isolated Python environment for the pinned Noteri Worker Pool.

This capability never starts the authority or changes Task Scheduler. It uses
only the staged immutable requirements and a fixed host-local destination.
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
import sys
import venv
from pathlib import Path

from scripts import noteri_worker_pool_activation_preflight as preflight
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_stage as stage

SOURCE_SHA = reference.SOURCE_SHA
ROOT_RELATIVE = Path("ReqSys") / "NoteriWorkerPool"
CONFIRM = "PREPARE-NOTERI-WORKER-POOL-VENV"
SCHEMA = "1"
MIN_FREE_BYTES = 1024 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Blocked(RuntimeError):
    pass


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _paths(localappdata: Path) -> tuple[Path, Path, Path]:
    root = localappdata / ROOT_RELATIVE
    return root, root / "releases" / SOURCE_SHA, root / "venvs" / SOURCE_SHA


def _check_release(release: Path) -> str:
    stage.ensure_no_link_components(release)
    manifest_path = release / "manifest.json"
    if stage.is_link(manifest_path) or not manifest_path.is_file():
        raise Blocked("release_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict)
            or manifest.get("source_sha") != SOURCE_SHA
            or manifest.get("source_repo") != stage.EXPECTED_REPO
            or manifest.get("kind") != "noteri_worker_pool_stage_only"
            or manifest.get("activated") is not False
            or not stage.validate_staged(release, manifest)):
        raise Blocked("release_integrity")
    requirements_hash = manifest["files"].get("requirements.txt")
    if not isinstance(requirements_hash, str) or not SHA256.fullmatch(requirements_hash):
        raise Blocked("requirements_digest")
    preflight.required_packages(release / "requirements.txt")
    return requirements_hash


def _python(venv_root: Path) -> Path:
    return venv_root / "Scripts" / "python.exe"


def _installed(python: Path) -> dict[str, str]:
    result = subprocess.run(
        [str(python), "-B", "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=45, check=False,
    )
    if result.returncode != 0:
        raise Blocked("venv_pip_list_failed")
    rows = json.loads(result.stdout)
    if not isinstance(rows, list):
        raise Blocked("venv_package_inventory_invalid")
    packages: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise Blocked("venv_package_inventory_invalid")
        name, version = row.get("name"), row.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise Blocked("venv_package_inventory_invalid")
        packages[name.lower().replace("_", "-")] = version
    return packages


def _verify(venv_root: Path, requirements_hash: str, required: dict[str, str]) -> bool:
    stage.ensure_no_link_components(venv_root)
    manifest_path = venv_root / "noteri-venv-manifest.json"
    python = _python(venv_root)
    if not manifest_path.is_file() or stage.is_link(manifest_path) or not python.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict)
                or manifest.get("schema_version") != SCHEMA
                or manifest.get("source_sha") != SOURCE_SHA
                or manifest.get("requirements_sha256") != requirements_hash
                or manifest.get("python_sha256") != _hash_file(python)):
            return False
        installed = _installed(python)
        return all(installed.get(name) == version for name, version in required.items())
    except (OSError, ValueError, TypeError, Blocked):
        return False


def _safe_rollback(venv_root: Path, venv_parent: Path) -> None:
    if venv_root.parent != venv_parent or venv_root.name != SOURCE_SHA:
        raise Blocked("rollback_scope_invalid")
    if not venv_root.exists():
        return
    stage.ensure_no_link_components(venv_root)
    shutil.rmtree(venv_root)


def prepare(*, localappdata: Path, hostname: str, platform: str, profile: str | None,
            mode: str, confirm: str = "", python_version: tuple[int, int] | None = None,
            install=None) -> dict:
    base = {"schema_version": SCHEMA, "source_sha": SOURCE_SHA,
            "activated": False, "token_bytes_read": False, "state_changed": False}
    if platform != "nt" or hostname.casefold() != "noteri" or profile != "NORMAL":
        return {**base, "result": "BLOCKED_HOST_PROFILE"}
    if mode not in {"plan", "prepare"} or (mode == "prepare" and confirm != CONFIRM):
        return {**base, "result": "BLOCKED_ACTION"}
    if (python_version or sys.version_info[:2]) < (3, 11):
        return {**base, "result": "BLOCKED_PYTHON_VERSION"}
    root, release, venv_root = _paths(localappdata)
    try:
        requirements_hash = _check_release(release)
        credential = reference.qualify(localappdata=localappdata, hostname=hostname,
                                       profile=profile, platform=platform)
        if credential["result"] != "REFERENCE_PRIVATE_UNREAD":
            return {**base, "result": "BLOCKED_CREDENTIAL_REFERENCE"}
        required = preflight.required_packages(release / "requirements.txt")
        if venv_root.exists():
            return {**base, "result": "ALREADY_PREPARED" if _verify(
                venv_root, requirements_hash, required) else "BLOCKED_EXISTING_VENV"}
        if shutil.disk_usage(release).free < MIN_FREE_BYTES:
            return {**base, "result": "BLOCKED_DISK_SPACE"}
        if mode == "plan":
            return {**base, "result": "VENV_PLAN_READY", "requirements_sha256": requirements_hash}
        stage.ensure_no_link_components(venv_root)
        parent = venv_root.parent
        parent.mkdir(parents=True, exist_ok=True)
        lock = parent / ".prepare.lock"
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return {**base, "result": "BLOCKED_CONCURRENT_PREPARE"}
        os.close(fd)
        created = False
        try:
            if venv_root.exists():
                raise Blocked("concurrent_venv_present")
            created = True
            installer = install or _install
            installer(venv_root, release / "requirements.txt")
            python = _python(venv_root)
            installed = _installed(python)
            if not all(installed.get(name) == version for name, version in required.items()):
                raise Blocked("venv_versions_mismatch")
            manifest = {"schema_version": SCHEMA, "source_sha": SOURCE_SHA,
                        "requirements_sha256": requirements_hash,
                        "python_sha256": _hash_file(python)}
            (venv_root / "noteri-venv-manifest.json").write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
            if not _verify(venv_root, requirements_hash, required):
                raise Blocked("venv_readback_failed")
            return {**base, "result": "VENV_PREPARED", "state_changed": True,
                    "requirements_sha256": requirements_hash}
        except Exception:
            if created:
                _safe_rollback(venv_root, parent)
            return {**base, "result": "BLOCKED_PREPARE_ROLLED_BACK"}
        finally:
            lock.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError, KeyError, stage.StageBlocked, Blocked):
        return {**base, "result": "BLOCKED_INTEGRITY"}


def _install(venv_root: Path, requirements: Path) -> None:
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(venv_root)
    result = subprocess.run(
        [str(_python(venv_root)), "-B", "-m", "pip", "install", "--isolated",
         "--no-input", "--disable-pip-version-check", "-r", str(requirements)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, check=False,
    )
    if result.returncode != 0:
        raise Blocked("venv_pip_install_failed")
    check = subprocess.run([str(_python(venv_root)), "-B", "-m", "pip", "check"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=45, check=False)
    if check.returncode != 0:
        raise Blocked("venv_pip_check_failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "prepare"), default="plan")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    local = os.environ.get("LOCALAPPDATA", "")
    profile = None
    if local:
        try:
            profile = json.loads((Path(local) / reference.PROFILE_RELATIVE).read_text(
                encoding="utf-8")).get("profile")
        except (OSError, ValueError, AttributeError):
            pass
    payload = prepare(localappdata=Path(local), hostname=socket.gethostname(),
                      platform=os.name, profile=profile, mode=args.mode, confirm=args.confirm)
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["result"] in {"VENV_PLAN_READY", "VENV_PREPARED", "ALREADY_PREPARED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
