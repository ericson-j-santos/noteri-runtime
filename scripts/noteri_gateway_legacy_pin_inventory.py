#!/usr/bin/env python3
"""Read-only, bounded inventory of the original Noteri Gateway v1 pins.

This does not authorize an update. The canonical updater independently verifies
the pinned legacy state before taking a new v2 snapshot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
from pathlib import Path

INSTALL_ROOT = Path(r"C:\dev\chatgpt-command-gateway")
LEGACY_SOURCE_COMMIT = "8a34b2b0862affb98a9e094e89802fdc6df090c0"
BACKUP_NAME = re.compile(r"backup-[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z")
MAX_JSON_BYTES = 256 * 1024
MANAGED_FILES = {
    "bin/command_gateway.py", "bin/host_health_check.py",
    "bin/session_bootstrap.py", "bin/session_preflight.py",
    "bin/session_launcher.py", "bin/runner_version_preflight.py",
    "config/policy.json",
}


class PinInventoryBlocked(RuntimeError):
    pass


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return (path.is_symlink() or bool(getattr(info, "st_file_attributes", 0)
                                      & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def host_context() -> tuple[str, str]:
    return os.name, socket.gethostname()


def _read_json(root: Path, path: Path) -> tuple[dict, str]:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if os.path.commonpath((str(resolved_root), str(resolved))) != str(resolved_root):
        raise PinInventoryBlocked("PATH_OUTSIDE_INSTALL_ROOT")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or _reparse(path)
            or before.st_size > MAX_JSON_BYTES):
        raise PinInventoryBlocked("FILE_NOT_CONFINED")
    payload = path.read_bytes()
    after = path.lstat()
    if (len(payload) != before.st_size or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns):
        raise PinInventoryBlocked("FILE_CHANGED")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise PinInventoryBlocked("JSON_INVALID") from None
    if not isinstance(value, dict):
        raise PinInventoryBlocked("JSON_INVALID")
    return value, hashlib.sha256(payload).hexdigest()


def inventory(root: Path = INSTALL_ROOT) -> dict[str, object]:
    if host_context() != ("nt", "Noteri"):
        raise PinInventoryBlocked("NOTERI_WINDOWS_REQUIRED")
    if _reparse(root) or not root.is_dir():
        raise PinInventoryBlocked("INSTALL_ROOT_INVALID")
    receipt, receipt_sha = _read_json(root, root / "update-receipt.json")
    if (receipt.get("result") != "HOST_UPDATE_BLOCKED"
            or receipt.get("source_commit") != LEGACY_SOURCE_COMMIT
            or receipt.get("rollback_attempted") is not True
            or receipt.get("rollback_succeeded") is not False):
        raise PinInventoryBlocked("LEGACY_RECEIPT_STATE_INVALID")
    backup_value = receipt.get("backup_dir")
    if not isinstance(backup_value, str):
        raise PinInventoryBlocked("BACKUP_REFERENCE_INVALID")
    backup = Path(backup_value)
    if (not BACKUP_NAME.fullmatch(backup.name) or _reparse(backup)
            or backup.resolve(strict=True).parent != root.resolve(strict=True)):
        raise PinInventoryBlocked("BACKUP_REFERENCE_INVALID")
    manifest, manifest_sha = _read_json(root, backup / "rollback-manifest.json")
    if (manifest.get("version") != 1
            or manifest.get("install_root") != str(root.resolve(strict=True))
            or not isinstance(manifest.get("entries"), dict)
            or set(manifest["entries"]) != MANAGED_FILES):
        raise PinInventoryBlocked("LEGACY_MANIFEST_STATE_INVALID")
    # Re-read the receipt after the manifest to detect ordinary concurrent drift.
    if _read_json(root, root / "update-receipt.json")[1] != receipt_sha:
        raise PinInventoryBlocked("LEGACY_RECEIPT_CHANGED")
    if _read_json(root, backup / "rollback-manifest.json")[1] != manifest_sha:
        raise PinInventoryBlocked("LEGACY_MANIFEST_CHANGED")
    return {
        "result": "NOTERI_LEGACY_PIN_INVENTORY",
        "receipt_sha256": receipt_sha,
        "manifest_sha256": manifest_sha,
        "legacy_state_confirmed": False,
        "installation_authorized": False,
        "managed_runtime_changed": False,
    }


def main() -> int:
    try:
        print(json.dumps(inventory(), sort_keys=True))
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, PinInventoryBlocked) else "HOST_READ_FAILED"
        print(json.dumps({"result": "NOTERI_LEGACY_PIN_INVENTORY_BLOCKED",
                          "reason": code}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
