#!/usr/bin/env python3
"""Read-only audit of exactly two pinned Noteri Worker Pool release directories.

Detects absent, malformed, mismatching or intact immutable releases. Reads no
credentials and neither stages nor installs nor dispatches nor starts services.
Must run in a source-SHA-bound Command Gateway Risk1 Noteri DEV session.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
from pathlib import Path, PurePosixPath
from typing import Any

import noteri_control_plane_watchdog as watchdog
import noteri_worker_pool_native_stage as stage
from noteri_ollama_recovery_preflight import source_sha

OLD_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
CANDIDATE_SHA = "60ee445f8dc9526f445185500dc8a46feda3fdf0"
CONFIRM = "AUDIT-NOTERI-WORKER-POOL-RELEASES-READONLY"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
HASH64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILES = 800
MAX_TOTAL = 35 * 1024 * 1024


class Blocked(ValueError):
    pass


def _regular(path: Path) -> bool:
    return path.is_file() and not stage.is_link(path)


def _safe_relative(path: str) -> bool:
    if not isinstance(path, str) or len(path) > 200 or "\\" in path:
        return False
    p = PurePosixPath(path)
    return (not p.is_absolute() and p.as_posix() == path
            and all(part not in ("", ".", "..") and not part.startswith(".")
                    for part in p.parts)
            and path not in ("manifest.json",))


def _extra_category(name: str) -> str:
    # The unknown filename itself may be sensitive. Classify only; do not
    # emit absolute paths, names, file content or hidden file metadata.
    path = PurePosixPath(name)
    if "__pycache__" in path.parts or name.casefold().endswith(".pyc"):
        return "PYTHON_BYTECODE_CACHE"
    suffix = path.suffix.casefold()
    if suffix in (".lock", ".lck"):
        return "LOCK_FILE"
    if suffix in (".tmp", ".temp"):
        return "TEMPORARY_FILE"
    if suffix in (".log", ".out"):
        return "LOG_FILE"
    if suffix in (".py", ".sql", ".json", ".md"):
        return "UNMANIFESTED_SOURCE_OR_METADATA"
    return "UNKNOWN_EXTRA_FILE"


def _bytecode_source(name: str, expected: set[str]) -> str | None:
    """Return only an existing allowlisted source name, not arbitrary paths."""
    path = PurePosixPath(name)
    if (len(path.parts) < 3 or path.parts[-2] != "__pycache__"
            or re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*\.cpython-[0-9]{2,3}\.pyc",
                            path.name) is None):
        return None
    module = path.name.split(".cpython-", 1)[0] + ".py"
    source = PurePosixPath(*path.parts[:-2], module).as_posix()
    return source if source in expected else None


def audit_one(releases: Path, release_sha: str) -> dict[str, Any]:
    if release_sha not in (OLD_SHA, CANDIDATE_SHA):
        raise Blocked("RELEASE_SHA_NOT_ALLOWED")
    release = releases / release_sha
    if stage.is_link(releases) or stage.is_link(release):
        return {"result": "BLOCKED_SYMLINK"}
    if not release.exists():
        return {"result": "RELEASE_ABSENT"}
    if not release.is_dir():
        return {"result": "RELEASE_NOT_DIRECTORY"}
    manifest_path = release / "manifest.json"
    if not manifest_path.exists():
        return {"result": "MANIFEST_ABSENT"}
    if not _regular(manifest_path):
        return {"result": "MANIFEST_NOT_REGULAR"}
    try:
        if not 0 < manifest_path.stat().st_size <= 160 * 1024:
            return {"result": "MANIFEST_SIZE_INVALID"}
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return {"result": "MANIFEST_UNREADABLE"}
    if (type(manifest) is not dict
            or set(manifest) != {"schema_version", "kind", "source_sha",
                                  "source_repo", "activated", "files"}
            or manifest["schema_version"] != "1"
            or manifest["kind"] != "noteri_worker_pool_stage_only"
            or manifest["source_repo"] != stage.EXPECTED_REPO
            or manifest["source_sha"] != release_sha
            or manifest["activated"] is not False):
        return {"result": "MANIFEST_IDENTITY_MISMATCH"}
    files = manifest["files"]
    if (type(files) is not dict or not 1 <= len(files) <= MAX_FILES
            or not all(_safe_relative(path)
                       and type(digest) is str and HASH64.fullmatch(digest)
                       for path, digest in files.items())
            or not stage.REQUIRED.issubset(files)):
        return {"result": "MANIFEST_FILES_INVALID"}
    try:
        stage.ensure_no_link_components(release)
        observed: set[str] = set()
        for path in release.rglob("*"):
            if stage.is_link(path):
                return {"result": "BLOCKED_SYMLINK"}
            if path.is_file():
                observed.add(path.relative_to(release).as_posix())
            elif not path.is_dir():
                return {"result": "NONREGULAR_ENTRY"}
        observed.discard("manifest.json")
        missing = set(files).difference(observed)
        extra = observed.difference(files)
        if missing:
            return {
                "result": "RELEASE_FILES_MISSING_OR_EXTRA",
                "missing_count": len(missing),
                "extra_count": len(extra),
            }
        size = 0
        matches = 0
        for name in sorted(files):
            source = release.joinpath(*PurePosixPath(name).parts)
            if not _regular(source):
                return {"result": "NONREGULAR_ENTRY"}
            length = source.stat().st_size
            size += length
            if length > stage.MAX_FILE_SIZE or size > MAX_TOTAL:
                return {"result": "RELEASE_SIZE_INVALID"}
            digest = hashlib.sha256()
            with source.open("rb") as opened:
                for block in iter(lambda: opened.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != files[name]:
                return {"result": "RELEASE_BYTES_MISMATCH",
                        "files_verified_before_mismatch": matches}
            matches += 1
        if extra:
            return {
                "result": "RELEASE_EXTRA_FILES_VERIFIED_PAYLOAD",
                "missing_count": 0, "extra_count": len(extra),
                "extra_categories": sorted({_extra_category(path) for path in extra}),
                "extra_bytecode_source_modules": sorted(
                    source for path in extra
                    if (source := _bytecode_source(path, set(files))) is not None
                ),
                "manifest_files_sha256_verified": matches,
                "manifest_total_bytes_verified": size,
            }
        if not stage.validate_staged(release, manifest):
            return {"result": "RELEASE_REVALIDATION_FAILED"}
        return {"result": "RELEASE_VERIFIED", "files_verified": matches,
                "total_bytes_verified": size}
    except (OSError, ValueError, KeyError, stage.StageBlocked):
        return {"result": "RELEASE_READ_ERROR"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        if (not SHA40.fullmatch(args.expected_head)
                or not CORRELATION.fullmatch(args.correlation_id)
                or args.confirm != CONFIRM
                or os.name != "nt" or socket.gethostname().casefold() != "noteri"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != args.expected_head):
            raise Blocked("SESSION_SOURCE_HOST_PROFILE_NOT_ATTESTED")
        local = os.environ.get("LOCALAPPDATA")
        if not local or not Path(local).is_absolute():
            raise Blocked("LOCALAPPDATA_NOT_AVAILABLE")
        releases = Path(local) / "ReqSys" / "NoteriWorkerPool" / "releases"
        outcome = {
            "result": "WORKER_POOL_RELEASE_AUDIT_READONLY",
            "host": "Noteri", "profile": "NORMAL",
            "pinned_release_sha": OLD_SHA,
            "candidate_release_sha": CANDIDATE_SHA,
            "pinned_release": audit_one(releases, OLD_SHA),
            "candidate_release": audit_one(releases, CANDIDATE_SHA),
            "activated": False, "state_changed": False,
            "credentials_read": False, "dispatch_performed": False,
            "expected_head": args.expected_head,
            "correlation_id": args.correlation_id,
        }
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except Blocked as exc:
        print(json.dumps({"result": "WORKER_POOL_RELEASE_AUDIT_BLOCKED",
                          "reason": str(exc), "state_changed": False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
