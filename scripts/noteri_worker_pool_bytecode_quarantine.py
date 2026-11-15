#!/usr/bin/env python3
"""Quarantine exactly one proven non-manifest Python cache without deleting it.

Only for the old 21fd68... staged Noteri DEV Worker Pool release. The original
cache remains byte-for-byte in a separate same-volume quarantine. Never touches
the 38 signed release files, service, tokens, credentials, UAC or package installs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
from pathlib import Path

import noteri_control_plane_watchdog as watchdog
import noteri_worker_pool_native_stage as stage
from noteri_ollama_recovery_preflight import source_sha
from noteri_worker_pool_release_audit_readonly import OLD_SHA, audit_one

CONFIRM = "QUARANTINE-ONE-NOTERI-WORKER-POOL-PYC-DEV"
ACTION = "noteri.worker_pool.bytecode.quarantine.v1"
IDEMPOTENCY = "noteri:worker-pool:secure-file-pyc:21fd68:dev:v1"
PY_CACHE = re.compile(r"secure_file\.cpython-[0-9]{2,3}\.pyc\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORR = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
MAX_CACHE_SIZE = 2 * 1024 * 1024


class Blocked(ValueError):
    pass


def hash_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _exact_cache(releases: Path) -> tuple[Path, Path, str]:
    release = releases / OLD_SHA
    report = audit_one(releases, OLD_SHA)
    if (report.get("result") != "RELEASE_EXTRA_FILES_VERIFIED_PAYLOAD"
            or report.get("missing_count") != 0
            or report.get("extra_count") != 1
            or report.get("extra_categories") != ["PYTHON_BYTECODE_CACHE"]
            or report.get("extra_bytecode_source_modules") != ["app/secure_file.py"]
            or report.get("manifest_files_sha256_verified") != 38):
        raise Blocked("RELEASE_NOT_EXACTLY_ONE_VERIFIED_SECURE_PYC")
    folder = release / "app" / "__pycache__"
    if (stage.is_link(folder) or not folder.is_dir()
            or stage.is_link(release)):
        raise Blocked("CACHE_DIRECTORY_UNTRUSTED")
    names = [path for path in folder.iterdir() if path.is_file()]
    if (len(names) != 1 or not PY_CACHE.fullmatch(names[0].name)
            or stage.is_link(names[0])
            or names[0].stat().st_nlink != 1
            or not 0 < names[0].stat().st_size <= MAX_CACHE_SIZE):
        raise Blocked("CACHE_ENTRY_NOT_SINGLE_REGULAR_FILE")
    cache = names[0]
    stage.ensure_no_link_components(cache)
    backup = releases / ".quarantine" / OLD_SHA / cache.name
    stage.ensure_no_link_components(backup)
    if backup.exists():
        raise Blocked("QUARANTINE_COLLISION")
    return cache, backup, hash_file(cache)


def assess(releases: Path) -> dict:
    report = audit_one(releases, OLD_SHA)
    if report.get("result") == "RELEASE_VERIFIED":
        backups = releases / ".quarantine" / OLD_SHA
        stage.ensure_no_link_components(backups)
        if backups.exists():
            if not backups.is_dir():
                raise Blocked("QUARANTINE_NOT_DIRECTORY")
            entries = list(backups.iterdir())
            if (len(entries) != 1 or not PY_CACHE.fullmatch(entries[0].name)
                    or stage.is_link(entries[0]) or not entries[0].is_file()
                    or entries[0].stat().st_nlink != 1
                    or not 0 < entries[0].stat().st_size <= MAX_CACHE_SIZE):
                raise Blocked("QUARANTINE_REPLAY_UNVERIFIED")
            return {
                "result": "ALREADY_QUARANTINED",
                "cache_sha256": hash_file(entries[0]),
                "manifest_files_sha256_verified": report["files_verified"],
                "state_changed": False,
            }
        return {"result": "RELEASE_CLEAN_ALREADY", "state_changed": False}
    cache, _backup, fingerprint = _exact_cache(releases)
    return {
        "result": "QUARANTINE_PLAN_READY",
        "cache_sha256": fingerprint,
        "cache_bytes": cache.stat().st_size,
        "manifest_files_sha256_verified": report["manifest_files_sha256_verified"],
        "state_changed": False,
    }


def quarantine(releases: Path) -> dict:
    # Only an immutable cache file can move; all 38 manifest files stay intact.
    releases_lock = releases / ".stage.lock"
    stage.ensure_no_link_components(releases_lock)
    try:
        fd = os.open(releases_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise Blocked("RELEASE_BUSY") from None
    except OSError:
        raise Blocked("RELEASE_LOCK_UNAVAILABLE") from None
    os.close(fd)
    moved = False
    cache: Path | None = None
    backup: Path | None = None
    try:
        state = assess(releases)
        if state["result"] != "QUARANTINE_PLAN_READY":
            return state
        cache, backup, original_sha = _exact_cache(releases)
        backup.parent.mkdir(parents=True, exist_ok=True)
        stage.ensure_no_link_components(backup)
        if backup.exists() or hash_file(cache) != original_sha:
            raise Blocked("CACHE_CHANGED_BEFORE_MOVE")
        os.rename(cache, backup)  # Preserve bytes; never unlink the cache.
        moved = True
        observed = audit_one(releases, OLD_SHA)
        if (observed.get("result") != "RELEASE_VERIFIED"
                or observed.get("files_verified") != 38
                or hash_file(backup) != original_sha):
            raise Blocked("POST_MOVE_READBACK_FAILED")
        return {
            "result": "CACHE_QUARANTINED_WITH_READBACK",
            "cache_sha256": original_sha,
            "manifest_files_sha256_verified": observed["files_verified"],
            "state_changed": True, "backup_verified": True,
            "cache_deleted": False, "service_started": False,
        }
    except (Blocked, OSError, ValueError, stage.StageBlocked):
        if moved and cache is not None and backup is not None:
            try:
                if not cache.exists() and backup.is_file():
                    os.rename(backup, cache)
            except OSError:
                raise Blocked("ROLLBACK_FAILED_NEEDS_HUMAN") from None
        raise
    finally:
        releases_lock.unlink(missing_ok=True)


def require_worker_api_idle() -> None:
    """Never mutate a release while its local Worker Pool API might be serving."""
    try:
        with socket.create_connection(("127.0.0.1", 8097), timeout=1):
            raise Blocked("WORKER_API_PORT_ACTIVE")
    except ConnectionRefusedError:
        return
    except Blocked:
        raise
    except OSError:
        raise Blocked("WORKER_API_PORT_STATUS_UNVERIFIED") from None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("plan", "apply"), required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--confirm", required=True)
    a = parser.parse_args()
    try:
        if (a.action != ACTION or a.idempotency_key != IDEMPOTENCY
                or not SHA40.fullmatch(a.expected_head)
                or not CORR.fullmatch(a.correlation_id)
                or os.name != "nt" or socket.gethostname().casefold() != "noteri"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != a.expected_head
                or (a.mode == "apply" and a.confirm != CONFIRM)
                or (a.mode == "plan" and a.confirm != "READ-ONLY")):
            raise Blocked("AUTHORITY_OR_SOURCE_NOT_ATTESTED")
        local = os.environ.get("LOCALAPPDATA")
        if not local or not Path(local).is_absolute():
            raise Blocked("LOCALAPPDATA_UNAVAILABLE")
        releases = Path(local) / "ReqSys" / "NoteriWorkerPool" / "releases"
        if a.mode == "apply":
            require_worker_api_idle()
        result = assess(releases) if a.mode == "plan" else quarantine(releases)
        result.update({
            "host": "Noteri", "profile": "NORMAL",
            "source_sha": a.expected_head,
            "correlation_id": a.correlation_id,
            "credentials_read": False, "installed_new_release": False,
            "mode": a.mode,
        })
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, stage.StageBlocked) as exc:
        print(json.dumps({
            "result": "QUARANTINE_BLOCKED",
            "reason": str(exc) if isinstance(exc, Blocked) else "IO_BLOCKED",
            "state_changed": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
