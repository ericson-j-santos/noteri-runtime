"""Read-only destination proof for the Noteri Worker Pool in-place maintenance.

This is a local sink-side check, NOT cross-host fencing, installation, or
authority to run. It must run before task stop/backup/quarantine/write/restart.
All caller environment fields are untrusted selectors and MUST match the
private durable Gateway counter and target-wide claim read from disk.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import socket
import stat
from pathlib import Path
from typing import Any

GATEWAY_RELATIVE = ("ReqSys", "CommandGateway", "noteri-worker-pool-fencing")
TARGET = r"\Automation\NoteriWorkerPoolApi"
KIND = "noteri-fencing-v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{3,128}\Z")
MAX_READ = 8192
MAX_SEQUENCE = 2**63 - 1


class SinkFenceBlocked(RuntimeError):
    pass


def _known_localappdata() -> Path:
    """Windows OS known folder; never take a state directory from arguments."""
    if os.name != "nt":
        raise SinkFenceBlocked("fence_host_not_windows")
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        rc = ctypes.windll.shell32.SHGetFolderPathW(
            None, 0x001c, None, 0, buffer
        )  # CSIDL_LOCAL_APPDATA
        if rc != 0 or not buffer.value:
            raise SinkFenceBlocked("fence_known_folder_unavailable")
        result = Path(buffer.value)
        if not result.is_absolute():
            raise SinkFenceBlocked("fence_known_folder_not_absolute")
        return result
    except (AttributeError, ValueError, OSError) as exc:
        raise SinkFenceBlocked("fence_known_folder_unavailable") from exc


def _json_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SinkFenceBlocked("fence_duplicate_json_key")
        result[key] = value
    return result


def _read_private_json(path: Path) -> dict[str, Any]:
    """Reject redirects, hardlinks, directory replacement and oversized data."""
    if not path.is_absolute():
        raise SinkFenceBlocked("fence_path_not_absolute")
    components = list(reversed([path, *path.parents]))
    try:
        identities = []
        for component in components:
            if component.is_symlink() or (
                hasattr(component, "is_junction") and component.is_junction()
            ):
                raise SinkFenceBlocked("fence_redirected_state_path")
            identity = os.stat(component, follow_symlinks=False)
            identities.append((component, identity.st_dev, identity.st_ino))
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            before = os.fstat(descriptor)
            entry = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (entry.st_dev, entry.st_ino)
                or not 0 < before.st_size <= MAX_READ):
                raise SinkFenceBlocked("fence_unsafe_state_file")
            with os.fdopen(descriptor, "rb", closefd=False) as file:
                raw = file.read(MAX_READ + 1)
            after = os.fstat(descriptor)
            if (len(raw) > MAX_READ or len(raw) != before.st_size
                or (after.st_dev, after.st_ino, after.st_size)
                    != (before.st_dev, before.st_ino, before.st_size)):
                raise SinkFenceBlocked("fence_state_changed_during_read")
            # A replacement may preserve size and the original descriptor.
            # Independently pin the current directory entry after the read.
            current_entry = os.stat(path, follow_symlinks=False)
            if ((current_entry.st_dev, current_entry.st_ino)
                    != (before.st_dev, before.st_ino)):
                raise SinkFenceBlocked("fence_state_replaced_during_read")
        finally:
            os.close(descriptor)
        # Recheck every ancestor; replacing a parent directory with another
        # tree can otherwise satisfy a single leaf inode inspection.
        for component, device, inode in identities:
            current = os.stat(component, follow_symlinks=False)
            if (component.is_symlink()
                or (hasattr(component, "is_junction") and component.is_junction())
                or (current.st_dev, current.st_ino) != (device, inode)):
                raise SinkFenceBlocked("fence_parent_or_entry_replaced")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_unique)
    except SinkFenceBlocked:
        raise
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise SinkFenceBlocked("fence_state_unavailable_or_corrupt") from exc
    if not isinstance(data, dict):
        raise SinkFenceBlocked("fence_state_not_object")
    return data


def _expected_counter(sequence: int, host: str) -> dict[str, Any]:
    base = {
        "kind": KIND, "target": TARGET, "host": host, "sequence": sequence,
    }
    serialized = json.dumps(
        base, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {**base, "sha256": hashlib.sha256(serialized).hexdigest()}


def _is_noteri() -> bool:
    return os.name == "nt" and socket.gethostname().casefold() == "noteri"


def require_active_fence() -> int:
    """Reject any caller that cannot prove the live Gateway claim on Noteri."""
    host = socket.gethostname()
    if not _is_noteri():
        raise SinkFenceBlocked("fence_wrong_host")
    env = os.environ
    raw_seq = env.get("NOTERI_POOL_MAINTENANCE_FENCE_SEQUENCE", "")
    nonce = env.get("NOTERI_POOL_MAINTENANCE_FENCE_NONCE", "")
    session = env.get("NOTERI_POOL_MAINTENANCE_SESSION_ID", "")
    correlation = env.get("NOTERI_POOL_MAINTENANCE_CORRELATION_ID", "")
    snapshot = env.get("NOTERI_POOL_MAINTENANCE_SNAPSHOT_SHA256", "")
    if (not re.fullmatch(r"[1-9][0-9]{0,18}", raw_seq)
        or not isinstance(nonce, str) or not NONCE.fullmatch(nonce)
        or not SESSION.fullmatch(session)
        or not CORRELATION.fullmatch(correlation)
        or not HEX64.fullmatch(snapshot)):
        raise SinkFenceBlocked("fence_request_missing_or_invalid")
    sequence = int(raw_seq)
    if sequence > MAX_SEQUENCE:
        raise SinkFenceBlocked("fence_sequence_overflow")
    known_folder = _known_localappdata()
    env_local = env.get("LOCALAPPDATA", "")
    if (not env_local or os.path.normcase(os.path.normpath(env_local))
        != os.path.normcase(os.path.normpath(str(known_folder)))):
        raise SinkFenceBlocked("fence_localappdata_override")
    root = known_folder.joinpath(*GATEWAY_RELATIVE)
    counter = _read_private_json(root / "counter.json")
    # The counter and active claim are in the same target-wide state folder.
    # No caller-supplied policy path, state root or claim contents are accepted.
    # Correct layout: <known folder>/ReqSys/CommandGateway/noteri-worker-pool-fencing/
    if counter != _expected_counter(sequence, host):
        raise SinkFenceBlocked("fence_counter_not_current")
    claim = _read_private_json(root / "active.claim")
    if (set(claim) != {
            "kind", "target", "host", "pid", "session_id",
            "correlation_id", "snapshot_sha256", "nonce", "sequence"
        } or claim.get("kind") != KIND or claim.get("target") != TARGET
        or claim.get("host") != host or type(claim.get("pid")) is not int
        or claim["pid"] != os.getppid()
        or claim.get("session_id") != session
        or claim.get("correlation_id") != correlation
        or claim.get("snapshot_sha256") != snapshot
        or claim.get("nonce") != nonce
        or type(claim.get("sequence")) is not int
        or claim["sequence"] != sequence):
        raise SinkFenceBlocked("fence_claim_not_owned_or_stale")
    return sequence
