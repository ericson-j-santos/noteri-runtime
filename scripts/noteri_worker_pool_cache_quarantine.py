#!/usr/bin/env python3
"""Governed fixed-path plan/quarantine of the single Noteri Worker Pool pyc.

The release remains immutable except for the removal of one independently
identified generated cache file. The file is moved (not deleted) to a
same-volume quarantine outside the release, where it is the rollback backup.
This script has no arbitrary path, URL or shell execution parameters.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import socket
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_release_audit as audit

SOURCE_SHA = reference.SOURCE_SHA
CACHE_RELATIVE = Path("app") / "__pycache__" / "secure_file.cpython-314.pyc"
CACHE_LABEL = CACHE_RELATIVE.as_posix()
QUARANTINE_FOLDER = Path("ReqSys") / "NoteriWorkerPool" / "quarantine" / SOURCE_SHA
CONFIRM = "QUARANTINE-NOTERI-WORKER-POOL-PYC"
RESTORE_CONFIRM = "RESTORE-NOTERI-WORKER-POOL-PYC"
BACKUP_RE = re.compile(r"secure_file[.]cpython-314[.]pyc[.]([0-9a-f]{64})[.]quarantined\Z")
BASE = {"schema_version": "1", "source_sha": SOURCE_SHA,
        "cache_relative": CACHE_LABEL, "service_changed": False,
        "activated": False, "secrets_read": False}


class Blocked(RuntimeError):
    pass


@contextmanager
def _exclusive(quarantine: Path):
    """Persistent lock is outside the immutable release; no shell or lease bypass."""
    parent = quarantine.parent
    stage.ensure_no_link_components(parent)
    parent.mkdir(parents=True, exist_ok=True)
    stage.ensure_no_link_components(parent)
    lock = parent / ".cache-quarantine.lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        yield
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)


def _backups(folder: Path) -> list[tuple[Path, str]]:
    if not folder.exists():
        return []
    stage.ensure_no_link_components(folder)
    if not folder.is_dir():
        raise Blocked("quarantine_invalid")
    items = []
    for file in folder.iterdir():
        if stage.is_link(file) or not file.is_file():
            raise Blocked("quarantine_unexpected_entry")
        match = BACKUP_RE.fullmatch(file.name)
        if match is None:
            raise Blocked("quarantine_unexpected_entry")
        if not 1 <= file.stat().st_size <= stage.MAX_FILE_SIZE:
            raise Blocked("quarantine_size")
        digest = stage.file_sha256(file)
        if digest != match.group(1):
            raise Blocked("quarantine_hash_mismatch")
        items.append((file, digest))
    if len(items) > 1:
        raise Blocked("quarantine_multiple_backups")
    return items


def _expected_audit(source: Path, release: Path, inspect_git: Callable) -> dict:
    report = audit.audit(source=source, release=release, profile="NORMAL",
                         hostname="Noteri", platform="nt", inspect_git=inspect_git)
    if report.get("source_identity_verified") is not True:
        raise Blocked("source_unverified")
    if report.get("installed_manifest") != "valid" or report.get("expected_file_count") < 1:
        raise Blocked("manifest_invalid")
    if report.get("missing") or report.get("hash_mismatch") or report.get("unsafe_entries"):
        raise Blocked("release_official_files_invalid")
    if report.get("manifest_metadata_mismatch") or any(
        report.get("counts", {}).get(name, -1) != 0
        for name in ("missing", "hash_mismatch", "unsafe", "manifest_keys_missing",
                     "manifest_keys_extra", "manifest_hash_mismatch")
    ):
        raise Blocked("release_manifest_mismatch")
    return report


def operate(*, source: Path, release: Path, quarantine: Path, profile: str,
            hostname: str, platform: str, mode: str,
            confirm: str = "", inactive: bool = False,
            inspect_git: Callable = stage.git_identity) -> dict:
    base = dict(BASE)
    if hostname.casefold() != "noteri" or platform != "nt" or profile != "NORMAL":
        return {**base, "result": "BLOCKED_HOST_PROFILE", "state_changed": False}
    if not inactive:
        return {**base, "result": "BLOCKED_SERVICE_NOT_ATTESTED_IDLE", "state_changed": False}
    if mode not in ("plan", "quarantine", "restore"):
        return {**base, "result": "BLOCKED_MODE", "state_changed": False}
    if mode == "quarantine" and confirm != CONFIRM:
        return {**base, "result": "BLOCKED_CONFIRMATION", "state_changed": False}
    if mode == "restore" and confirm != RESTORE_CONFIRM:
        return {**base, "result": "BLOCKED_CONFIRMATION", "state_changed": False}
    try:
        stage.ensure_no_link_components(source)
        stage.ensure_no_link_components(release)
        stage.ensure_no_link_components(quarantine)
        cache = release / CACHE_RELATIVE
        stage.ensure_no_link_components(cache)
        report = _expected_audit(source, release, inspect_git)
        backups = _backups(quarantine)
        extra = report.get("extra", [])
        if extra == [] and report.get("result") == "RELEASE_INTACT":
            if len(backups) != 1:
                return {**base, "result": "BLOCKED_BACKUP_NOT_PROVEN",
                        "state_changed": False}
            if mode == "restore":
                backup, digest = backups[0]
                with _exclusive(quarantine):
                    if cache.exists() or stage.is_link(cache):
                        raise Blocked("cache_conflict")
                    if _backups(quarantine) != backups:
                        raise Blocked("quarantine_concurrent")
                    os.rename(backup, cache)
                    after = _expected_audit(source, release, inspect_git)
                    if after.get("extra") != [CACHE_LABEL]:
                        # Restore failed to return the exact recorded initial state.
                        if not backup.exists() and cache.exists():
                            os.rename(cache, backup)
                        raise Blocked("restore_readback_failed")
                return {**base, "result": "CACHE_RESTORED", "state_changed": True,
                        "cache_sha256": digest, "backup_preserved": False}
            return {**base, "result": "ALREADY_QUARANTINED",
                    "state_changed": False, "cache_sha256": backups[0][1],
                    "backup_preserved": True}
        if extra != [CACHE_LABEL] or report["counts"].get("extra") != 1:
            raise Blocked("other_release_entries_present")
        if backups:
            raise Blocked("quarantine_destination_already_present")
        if not cache.is_file() or stage.is_link(cache):
            raise Blocked("cache_not_regular")
        if not 1 <= cache.stat().st_size <= stage.MAX_FILE_SIZE:
            raise Blocked("cache_size")
        with cache.open("rb") as handle:
            if handle.read(4) != importlib.util.MAGIC_NUMBER:
                raise Blocked("cache_magic_mismatch")
        digest = stage.file_sha256(cache)
        if stage.file_sha256(cache) != digest:
            raise Blocked("cache_changed_during_preflight")
        if mode == "plan":
            return {**base, "result": "QUARANTINE_PLAN_READY",
                    "state_changed": False, "cache_sha256": digest,
                    "backup_preserved": False}
        if mode == "restore":
            raise Blocked("restore_requires_quarantined_cache")
        # The move itself is the lossless backup. Never overwrite or remove a
        # cache or backup and never copy the content to an unvalidated location.
        with _exclusive(quarantine):
            quarantine.mkdir(parents=True, exist_ok=True)
            stage.ensure_no_link_components(quarantine)
            if _backups(quarantine):
                raise Blocked("quarantine_concurrent")
            dest = quarantine / f"{CACHE_RELATIVE.name}.{digest}.quarantined"
            if dest.exists() or stage.is_link(dest):
                raise Blocked("destination_exists")
            if stage.file_sha256(cache) != digest:
                raise Blocked("cache_changed_before_move")
            if _expected_audit(source, release, inspect_git).get("extra") != [CACHE_LABEL]:
                raise Blocked("release_changed_before_move")
            os.rename(cache, dest)
            try:
                if stage.file_sha256(dest) != digest:
                    raise Blocked("quarantine_readback_hash")
                after = _expected_audit(source, release, inspect_git)
                if after.get("result") != "RELEASE_INTACT":
                    raise Blocked("release_readback_not_intact")
            except Exception:
                if (not cache.exists() and not stage.is_link(cache)
                        and dest.is_file() and not stage.is_link(dest)
                        and stage.file_sha256(dest) == digest):
                    os.rename(dest, cache)
                raise
        return {**base, "result": "CACHE_QUARANTINED",
                "state_changed": True, "cache_sha256": digest,
                "backup_preserved": True, "release_intact": True}
    except (OSError, ValueError, TypeError, KeyError, Blocked, stage.StageBlocked):
        return {**base, "result": "BLOCKED_GOVERNED_QUARANTINE",
                "state_changed": False, "state_may_have_changed": mode != "plan"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "quarantine", "restore"), default="plan")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        result = {**BASE, "result": "BLOCKED_HOST_PROFILE", "state_changed": False}
    else:
        root = Path(local)
        try:
            profile = json.loads((root / reference.PROFILE_RELATIVE).read_text(
                encoding="utf-8")).get("profile")
        except (OSError, ValueError, TypeError):
            profile = None
        # Only explicitly verified idle native runtimes may have their staged
        # files moved; a listener or ambiguous scheduled task blocks.
        inactive = False
        if socket.gethostname().casefold() == "noteri" and os.name == "nt":
            from scripts import noteri_worker_pool_native_activation as activation
            inactive = (activation.listener_absent() and
                        activation.task_absent(Path(os.environ.get("WINDIR", "C:\\Windows"))))
        source = (root / "ReqSys" / "NoteriRuntimeRunner" / "_work" /
                  "noteri-runtime" / "noteri-runtime" / "_worker_pool")
        release = root / reference.RELEASES_RELATIVE / SOURCE_SHA
        result = operate(source=source, release=release,
                         quarantine=root / QUARANTINE_FOLDER, profile=profile,
                         hostname=socket.gethostname(), platform=os.name,
                         mode=args.mode, confirm=args.confirm, inactive=inactive)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] in (
        "QUARANTINE_PLAN_READY", "CACHE_QUARANTINED",
        "ALREADY_QUARANTINED", "CACHE_RESTORED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
