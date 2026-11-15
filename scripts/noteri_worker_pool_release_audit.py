#!/usr/bin/env python3
"""Read-only, source-pinned audit of the existing Noteri Worker Pool release.

This command is intentionally not a repair, installer or activation path.
Only the expected source checkout and the immutable release are inspected.
Credentials, arbitrary paths, file contents and private absolute paths are
never included in its output.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
from pathlib import Path, PurePosixPath
from typing import Callable

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as reference

SOURCE_SHA = reference.SOURCE_SHA
MAX_MANIFEST_BYTES = 131072
MAX_ENTRIES = stage.MAX_FILES + 100
MAX_DETAILS = 60
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
PRIVATE_TERMS = ("token", "password", "credential", "secret", "private", "pem", "pfx", "key")
BASE = {"schema_version": "1", "source_sha": SOURCE_SHA,
        "state_changed": False, "secrets_read": False, "activated": False,
        "execution_authorized": False, "scope": "pinned_release_only"}


class AuditBlocked(Exception):
    pass


def _safe_relative(value: str) -> str:
    """Show official paths and the one known generated cache path, never secrets."""
    if re.fullmatch(r"app/__pycache__/secure_file[.]cpython-(?:311|312|313|314)[.]pyc",
                    value):
        # The cache contains generated Python bytecode, not an allowlisted
        # release file. Disclosing its fixed relative name is safe; do not
        # open its contents or silently permit it inside the immutable tree.
        return value
    parts = PurePosixPath(value).parts
    allowed = (len(parts) >= 2 and parts[0] == "app") or (
        len(parts) >= 3 and parts[:2] == ("contracts", "v1"))
    if (allowed and len(value) <= 180 and
            all(SAFE_NAME.fullmatch(part) for part in parts) and
            not any(part.startswith(".") or any(term in part.lower() for term in PRIVATE_TERMS)
                    for part in parts) and
            PurePosixPath(value).suffix in stage.SUFFIXES):
        return value
    return "redacted:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _bounded(values: list) -> tuple[list, bool]:
    return values[:MAX_DETAILS], len(values) > MAX_DETAILS


def _inventory(release: Path) -> tuple[set[str], set[str]]:
    """Do not follow reparse points, symlinks, or any unexpected file."""
    found: set[str] = set()
    unsafe: set[str] = set()
    pending = [release]
    seen = 0
    while pending:
        parent = pending.pop()
        for entry in parent.iterdir():
            seen += 1
            if seen > MAX_ENTRIES:
                raise AuditBlocked("release_inventory_limit")
            name = entry.relative_to(release).as_posix()
            if stage.is_link(entry):
                unsafe.add(name)
            elif entry.is_dir():
                pending.append(entry)
            elif entry.is_file():
                if name != "manifest.json":
                    found.add(name)
            else:
                unsafe.add(name)
    return found, unsafe


def _manifest(release: Path) -> tuple[str, dict | None, str | None]:
    target = release / "manifest.json"
    if stage.is_link(target):
        return "unsafe", None, None
    if not target.is_file():
        return "missing", None, None
    if target.stat().st_size > MAX_MANIFEST_BYTES:
        return "invalid", None, None
    raw = target.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        return "invalid", None, None
    digest = hashlib.sha256(raw).hexdigest()
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        return "invalid", None, digest
    if (type(parsed) is not dict or
            type(parsed.get("files")) is not dict or
            len(parsed["files"]) > stage.MAX_FILES or
            any(type(k) is not str or len(k) > 240 or
                type(v) is not str or not re.fullmatch(r"[0-9a-f]{64}", v)
                for k, v in parsed["files"].items())):
        return "invalid", None, digest
    return "valid", parsed, digest


def audit(*, source: Path, release: Path, profile: str,
          hostname: str, platform: str,
          inspect_git: Callable = stage.git_identity) -> dict:
    base = dict(BASE)
    if platform != "nt" or hostname.casefold() != "noteri" or profile != "NORMAL":
        return {**base, "result": "BLOCKED_HOST_PROFILE"}
    if not stage.SHA40.fullmatch(SOURCE_SHA):
        return {**base, "result": "BLOCKED_SOURCE"}
    try:
        stage.ensure_no_link_components(source)
        observed_sha, remote, dirty = inspect_git(source)
        if observed_sha != SOURCE_SHA or remote not in stage.ORIGINS or dirty:
            return {**base, "result": "BLOCKED_SOURCE_IDENTITY"}
        expected = stage.build_manifest(SOURCE_SHA, stage.safe_source_files(source))
        stage.ensure_no_link_components(release)
        if not release.is_dir():
            return {**base, "result": "RELEASE_MISSING",
                    "expected_file_count": len(expected["files"])}
        manifest_state, stored, manifest_digest = _manifest(release)
        found, unsafe = _inventory(release)
        wanted = set(expected["files"])
        missing = sorted(wanted - found)
        extra = sorted(found - wanted)
        changed = []
        for name in sorted(wanted & found):
            file = release / name
            if stage.is_link(file) or not file.is_file():
                unsafe.add(name)
                continue
            if file.stat().st_size > stage.MAX_FILE_SIZE:
                unsafe.add(name)
                continue
            actual = stage.file_sha256(file)
            if actual != expected["files"][name]:
                changed.append({"path": name, "expected_sha256": expected["files"][name],
                                "observed_sha256": actual})
        metadata_diff = []
        manifest_missing, manifest_extra, manifest_changed = [], [], []
        if stored is not None:
            metadata_diff = sorted(k for k in (
                "schema_version", "kind", "source_sha", "source_repo", "activated")
                if stored.get(k) != expected[k])
            manifest_missing = sorted(wanted - set(stored["files"]))
            manifest_extra = sorted(set(stored["files"]) - wanted)
            manifest_changed = sorted(k for k in wanted & set(stored["files"])
                                      if stored["files"][k] != expected["files"][k])
        if (manifest_digest is not None and (release / "manifest.json").is_file()
                and stage.file_sha256(release / "manifest.json") != manifest_digest):
            return {**base, "result": "BLOCKED_CONCURRENT_CHANGE"}
        if inspect_git(source) != (observed_sha, remote, dirty):
            return {**base, "result": "BLOCKED_CONCURRENT_CHANGE"}
        missing_out, t1 = _bounded(missing)
        extra_out, t2 = _bounded([_safe_relative(s) for s in extra])
        unsafe_out, t3 = _bounded([_safe_relative(s) for s in sorted(unsafe)])
        changed_out, t4 = _bounded(changed)
        manifest_missing_out, t5 = _bounded(manifest_missing)
        manifest_extra_out, t6 = _bounded([_safe_relative(s) for s in manifest_extra])
        manifest_changed_out, t7 = _bounded(manifest_changed)
        counts = {"missing": len(missing), "extra": len(extra),
                  "hash_mismatch": len(changed), "unsafe": len(unsafe),
                  "manifest_keys_missing": len(manifest_missing),
                  "manifest_keys_extra": len(manifest_extra),
                  "manifest_hash_mismatch": len(manifest_changed)}
        intact = (manifest_state == "valid" and stored == expected
                  and not any(counts.values()))
        return {
            **base, "result": "RELEASE_INTACT" if intact else "RELEASE_MISMATCH",
            "source_identity_verified": True, "expected_file_count": len(wanted),
            "installed_manifest": manifest_state, "manifest_metadata_mismatch": metadata_diff,
            "counts": counts, "missing": missing_out, "extra": extra_out,
            "hash_mismatch": changed_out, "unsafe_entries": unsafe_out,
            "manifest_keys_missing": manifest_missing_out,
            "manifest_keys_extra": manifest_extra_out,
            "manifest_hash_mismatch": manifest_changed_out,
            "details_truncated": any((t1, t2, t3, t4, t5, t6, t7)),
        }
    except (OSError, ValueError, TypeError, KeyError, stage.StageBlocked,
            AuditBlocked):
        return {**base, "result": "BLOCKED_READ_ONLY_INTEGRITY"}


def main() -> int:
    # No user-supplied file path, URL, shell command, SHA or manifest selection.
    local_str = os.environ.get("LOCALAPPDATA", "")
    if not local_str:
        result = {**BASE, "result": "BLOCKED_HOST_PROFILE"}
    else:
        local = Path(local_str)
        profile_path = local / reference.PROFILE_RELATIVE
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8")).get("profile")
        except (OSError, ValueError, AttributeError):
            profile = None
        # Fixed existing runner checkout; never fetch or execute its contents.
        source = (local / "ReqSys" / "NoteriRuntimeRunner" / "_work" /
                  "noteri-runtime" / "noteri-runtime" / "_worker_pool")
        release = local / reference.RELEASES_RELATIVE / SOURCE_SHA
        result = audit(source=source, release=release, profile=profile,
                       hostname=socket.gethostname(), platform=os.name)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "RELEASE_INTACT" else 2


if __name__ == "__main__":
    raise SystemExit(main())
