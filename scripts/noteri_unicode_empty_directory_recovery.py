#!/usr/bin/env python3
"""Bounded reversible recovery core for the Noteri invalid-Unicode Git entry.

This module is NOT an installed recovery service. The command line is
read-only by construction. The state-changing core can only be used by an
installed, independently admitted authority which supplies an exclusive_claim
context manager and performs session fencing. Do not substitute a local lock
or a historical session reservation for that authority.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import unicodedata

HOST = "noteri"
EXPECTED_HEAD = "9840ec316ba5d76f17cd1cf113d208ed649daf7d"
NAME_SHA256 = "8bf5d2badf76dfee095b8e6784af2f24231fe5bc5774b83736e2141897a12159"
ROOT = Path(r"C:\dev\chatgpt-workers")
TARGETS = frozenset((
    "wt-chat-noteri-six-pspath-9840-20261115",
    "wt-chat-noteri-six-pspath-fresh-9840-20261115",
))
ID = re.compile(r"^[A-Za-z0-9._:-]{12,128}$")
WARNING = re.compile(rb"could not open directory ['\"]([^'\"]{1,128})['\"]:", re.I)
PROBE_CMD = ("git", "ls-files", "--others", "--exclude-standard", "-z", "--", ".")


class Blocked(RuntimeError):
    pass


def _warning_identity(raw: bytes) -> str:
    matched = WARNING.search(raw)
    if not matched:
        raise Blocked("WARNING_IDENTITY_NOT_FOUND")
    name = matched.group(1)
    if hashlib.sha256(name).hexdigest() != NAME_SHA256:
        raise Blocked("WARNING_IDENTITY_MISMATCH")
    try:
        value = name.decode("utf-8")
    except UnicodeError as exc:
        raise Blocked("WARNING_ENCODING_UNVERIFIED") from exc
    if "/" not in value or value.count("/") != 1 or not value.endswith("/"):
        raise Blocked("WARNING_NOT_SINGLE_DIRECTORY")
    return value[:-1]


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ("git", *args), cwd=root, capture_output=True,
            timeout=20, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("GIT_PROBE_UNAVAILABLE") from exc


def _validate_root(root: Path, target: str) -> None:
    if target not in TARGETS:
        raise Blocked("TARGET_DENIED")
    intended = ROOT / target
    if os.path.normcase(os.path.abspath(root)) != os.path.normcase(os.path.abspath(intended)):
        raise Blocked("TARGET_LOCATION_MISMATCH")
    if root.is_symlink() or not root.is_dir() or root.parent.is_symlink():
        raise Blocked("TARGET_DIRECTORY_UNTRUSTED")
    top = _git(root, "rev-parse", "--show-toplevel")
    head = _git(root, "rev-parse", "HEAD")
    if top.returncode or top.stderr or head.returncode or head.stderr:
        raise Blocked("GIT_IDENTITY_UNAVAILABLE")
    if os.path.normcase(os.path.normpath(os.fsdecode(top.stdout).strip())) != os.path.normcase(os.path.normpath(str(root))):
        raise Blocked("GIT_ROOT_MISMATCH")
    if head.stdout.strip().decode("ascii", "replace") != EXPECTED_HEAD:
        raise Blocked("HEAD_MISMATCH")


def _matching_directory(root: Path, warning: str) -> Path:
    matches = []
    for item in root.iterdir():
        name = item.name
        reconstructed = "".join(
            "\ufffd" if unicodedata.category(char) == "Cs" else char
            for char in name
        )
        if reconstructed != warning:
            continue
        if item.is_symlink() or not item.is_dir():
            raise Blocked("MATCHED_ENTRY_NOT_PLAIN_DIRECTORY")
        if any(item.iterdir()):
            raise Blocked("MATCHED_ENTRY_NOT_EMPTY")
        matches.append(item)
    if len(matches) != 1:
        raise Blocked("DIRECTORY_NOT_UNIQUE")
    return matches[0]


def _probe(root: Path, *, expect_warning: bool) -> tuple[Path | None, bytes]:
    result = _git(root, *PROBE_CMD[1:])
    if result.returncode:
        raise Blocked("GIT_UNTRACKED_FAILED")
    if expect_warning:
        if not result.stderr.startswith(b"warning: "):
            raise Blocked("UNEXPECTED_GIT_STDERR")
        name = _warning_identity(result.stderr)
        return _matching_directory(root, name), result.stderr
    if result.stderr:
        raise Blocked("GIT_WARNING_PERSISTS")
    return None, b""


def _destination(quarantine: Path, target: str) -> Path:
    # ASCII destination derived from two fixed IDs and fixed content identity.
    digest = hashlib.sha256((target + ":" + NAME_SHA256).encode("ascii")).hexdigest()[:20]
    return quarantine / ("noteri-invalid-unicode-" + digest)


def _safe_quarantine(root: Path, quarantine: Path) -> None:
    # The authority owns/validates the configured private state root.
    if quarantine.is_symlink() or root == quarantine or quarantine.is_relative_to(root):
        raise Blocked("QUARANTINE_LOCATION_DENIED")
    if quarantine.exists() and not quarantine.is_dir():
        raise Blocked("QUARANTINE_NOT_DIRECTORY")
    for item in (quarantine, quarantine.parent):
        if item.is_symlink():
            raise Blocked("QUARANTINE_LINK_DENIED")


def preview(root: Path, target: str) -> dict:
    """No mutations, no arbitrary paths/filenames or command in the receipt."""
    _validate_root(root, target)
    src, warning = _probe(root, expect_warning=True)
    assert src is not None
    return {
        "result": "RECOVERY_PREFLIGHT_ONLY",
        "target": target,
        "source_head": EXPECTED_HEAD,
        "warning_sha256": hashlib.sha256(warning).hexdigest(),
        "empty_directory": True,
        "exclusive_lease_proven": False,
        "apply_authorized": False,
        "state_changed": False,
    }


def recover_with_authority(root: Path, target: str, quarantine: Path, *,
                           authority: object, idempotency_key: str,
                           correlation_id: str) -> dict:
    """Maintenance core; NEVER call without the installed owning controller.

    authority.exclusive_claim must validate host, original-session ownership,
    non-overlap with every worker, fencing and a durable idempotency key, then
    retain exclusive ownership during this complete with-block.
    """
    if not ID.fullmatch(idempotency_key) or not ID.fullmatch(correlation_id):
        raise Blocked("REQUEST_ID_INVALID")
    if target not in TARGETS:
        raise Blocked("TARGET_DENIED")
    if authority is None or not callable(getattr(authority, "exclusive_claim", None)):
        raise Blocked("AUTHORITY_NOT_INSTALLED")
    claim = authority.exclusive_claim(
        target=target, expected_head=EXPECTED_HEAD,
        idempotency_key=idempotency_key, correlation_id=correlation_id,
    )
    if claim is None:
        raise Blocked("AUTHORITY_LEASE_DENIED")
    with claim as permit:
        if getattr(permit, "fencing_proven", False) is not True:
            raise Blocked("AUTHORITY_FENCING_UNVERIFIED")
        if getattr(permit, "target", None) != target or getattr(permit, "source_head", None) != EXPECTED_HEAD:
            raise Blocked("AUTHORITY_TARGET_MISMATCH")
        _validate_root(root, target)
        _safe_quarantine(root, quarantine)
        destination = _destination(quarantine, target)
        if destination.is_symlink():
            raise Blocked("QUARANTINE_DESTINATION_LINK")
        current = _git(root, *PROBE_CMD[1:])
        if current.returncode:
            raise Blocked("GIT_UNTRACKED_FAILED")
        if destination.exists():
            # Replay is allowed only for the same key according to the
            # owning controller; never overwrite a quarantine destination.
            if current.stderr or not destination.is_dir() or any(destination.iterdir()):
                raise Blocked("REPLAY_STATE_MISMATCH")
            return {"result": "ALREADY_QUARANTINED", "target": target,
                    "state_changed": False, "idempotency_key": idempotency_key}
        src, _ = _probe(root, expect_warning=True)
        assert src is not None
        original_stat = src.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(original_stat.st_mode) or src.is_symlink()
                or any(src.iterdir())):
            raise Blocked("SOURCE_NOT_EMPTY_OR_CHANGED")
        if quarantine.parent.is_symlink():
            raise Blocked("QUARANTINE_PARENT_LINK")
        quarantine.mkdir(parents=True, exist_ok=True)
        _safe_quarantine(root, quarantine)
        if (destination.exists() or src.is_symlink()
                or src.stat(follow_symlinks=False).st_ino != original_stat.st_ino
                or any(src.iterdir())):
            raise Blocked("PREMOVE_STATE_CHANGED")
        src.rename(destination)
        try:
            if src.exists() or not destination.is_dir() or any(destination.iterdir()):
                raise Blocked("POSTMOVE_DIRECTORY_MISMATCH")
            _probe(root, expect_warning=False)
        except BaseException:
            if destination.is_dir() and not src.exists() and not any(destination.iterdir()):
                destination.rename(src)
            raise
        return {"result": "QUARANTINED_REVERSIBLY", "target": target,
                "state_changed": True, "rollback_available": destination.is_dir(),
                "idempotency_key": idempotency_key}


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only recovery availability")
    parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    if (os.name != "nt" or socket.gethostname().casefold() != HOST
            or args.expected_head != EXPECTED_HEAD
            or not ID.fullmatch(args.correlation_id)):
        print(json.dumps({"result": "BLOCKED_HOST_OR_SOURCE"}))
        return 2
    try:
        result = preview(ROOT / args.target, args.target)
    except Blocked as exc:
        print(json.dumps({"result": "PREFLIGHT_BLOCKED", "reason": str(exc)}))
        return 2
    print(json.dumps(result, sort_keys=True))
    # The installed controller (not this CLI) must admit/apply maintenance.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
