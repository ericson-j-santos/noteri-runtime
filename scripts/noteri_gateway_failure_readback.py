#!/usr/bin/env python3
"""Read-only, sanitized post-failure inventory of the Noteri Gateway update."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
from pathlib import Path

ROOT = Path(r"C:\dev\chatgpt-command-gateway")
MANAGED = frozenset({
    "bin/command_gateway.py", "bin/host_health_check.py",
    "bin/session_bootstrap.py", "bin/session_preflight.py",
    "bin/session_launcher.py", "bin/runner_version_preflight.py",
    "config/policy.json",
})
BACKUP_NAME = re.compile(r"backup-[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CURRENT_DIAGNOSTIC_RULES_SHA = "b5ade370fa11877ff7b899b5c6feacc3bfaf34e7"


class ReadbackBlocked(RuntimeError):
    pass


def host_context() -> tuple[str, str]:
    return os.name, socket.gethostname()


def _regular(path: Path, *, limit: int = 1024 * 1024) -> bytes:
    for component in (path, *path.parents):
        if not component.exists():
            raise ReadbackBlocked("FILE_MISSING")
        info = component.lstat()
        if component.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ReadbackBlocked("REPARSE_PATH")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ReadbackBlocked("FILE_SHAPE_INVALID")
    raw = path.read_bytes()
    after = path.stat()
    if len(raw) != before.st_size or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ReadbackBlocked("FILE_CHANGED")
    return raw


def _json(path: Path) -> tuple[dict, str]:
    raw = _regular(path)
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError):
        raise ReadbackBlocked("JSON_INVALID") from None
    if not isinstance(value, dict):
        raise ReadbackBlocked("JSON_INVALID")
    return value, hashlib.sha256(raw).hexdigest()


def _state(path: Path, digest: object, size: object) -> bool:
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ReadbackBlocked("SNAPSHOT_DIGEST_INVALID")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ReadbackBlocked("SNAPSHOT_SIZE_INVALID")
    try:
        raw = _regular(path, limit=4 * 1024 * 1024)
    except ReadbackBlocked as exc:
        if str(exc) == "FILE_MISSING":
            return False
        raise
    return len(raw) == size and hashlib.sha256(raw).hexdigest() == digest


def _select_receipt(root: Path) -> tuple[dict, Path, str, str, dict, str]:
    primary_path = root / "update-receipt.json"
    primary, primary_sha = _json(primary_path)
    recoveries: list[tuple[Path, re.Match[str]]] = []
    for path in root.iterdir():
        match = RECOVERY_NAME.fullmatch(path.name)
        if match:
            recoveries.append((path, match))
    if len(recoveries) > 16:
        raise ReadbackBlocked("RECOVERY_RECEIPT_INVENTORY_AMBIGUOUS")
    current: list[tuple[dict, Path, str]] = []
    for path, match in recoveries:
        candidate, candidate_sha = _json(path)
        if candidate.get("source_commit") != CURRENT_DIAGNOSTIC_RULES_SHA:
            continue
        if (
            candidate.get("result") != "HOST_UPDATE_BLOCKED"
            or candidate.get("transaction_id") != match.group(1)
            or not isinstance(candidate.get("primary_receipt_error"), str)
            or not candidate["primary_receipt_error"]
        ):
            raise ReadbackBlocked("RECOVERY_RECEIPT_INVALID")
        current.append((candidate, path, candidate_sha))
    if primary.get("source_commit") == CURRENT_DIAGNOSTIC_RULES_SHA:
        if current:
            raise ReadbackBlocked("RECOVERY_RECEIPT_CONFLICT")
        return primary, primary_path, primary_sha, "primary", primary, primary_sha
    if len(current) > 1:
        raise ReadbackBlocked("RECOVERY_RECEIPT_AMBIGUOUS")
    if current:
        receipt, receipt_path, receipt_sha = current[0]
        return receipt, receipt_path, receipt_sha, "recovery", primary, primary_sha
    return primary, primary_path, primary_sha, "primary", primary, primary_sha


def inventory(root: Path, legacy_receipt_sha: str, legacy_manifest_sha: str) -> dict:
    platform, host = host_context()
    if platform != "nt" or host.casefold() != "noteri":
        raise ReadbackBlocked("NOTERI_WINDOWS_REQUIRED")
    if not SHA256.fullmatch(legacy_receipt_sha) or not SHA256.fullmatch(legacy_manifest_sha):
        raise ReadbackBlocked("PIN_INVALID")
    if root.is_symlink() or not root.is_dir():
        raise ReadbackBlocked("ROOT_INVALID")
    receipt, receipt_path, receipt_sha, receipt_origin, primary_receipt, primary_receipt_sha = _select_receipt(root)
    backup_text = receipt.get("backup_dir")
    if not isinstance(backup_text, str):
        raise ReadbackBlocked("BACKUP_REFERENCE_INVALID")
    backup = Path(backup_text)
    if (not BACKUP_NAME.fullmatch(backup.name) or backup.is_symlink()
            or backup.resolve(strict=True).parent != root.resolve(strict=True)):
        raise ReadbackBlocked("BACKUP_REFERENCE_INVALID")
    manifest, manifest_sha = _json(backup / "rollback-manifest.json")
    entries = manifest.get("entries")
    if (manifest.get("version") not in (1, 2) or not isinstance(entries, dict)
            or set(entries) != MANAGED or manifest.get("install_root") != str(root.resolve(strict=True))):
        raise ReadbackBlocked("MANIFEST_INVALID")
    states = {}
    backup_integrity = True
    for relative in sorted(MANAGED):
        entry = entries[relative]
        if not isinstance(entry, dict) or not isinstance(entry.get("existed"), bool):
            raise ReadbackBlocked("ENTRY_INVALID")
        target = root.joinpath(*relative.split("/"))
        if entry["existed"]:
            previous = _state(target, entry.get("previous_sha256"), entry.get("previous_size"))
            saved = _state(backup / "files" / relative, entry.get("previous_sha256"), entry.get("previous_size"))
        else:
            previous = not target.exists() and not target.is_symlink()
            saved = not (backup / "files" / relative).exists()
        desired = (_state(target, entry.get("desired_sha256"), entry.get("desired_size"))
                   if manifest["version"] == 2 else None)
        states[relative] = {"previous_content": previous, "desired_content": desired}
        backup_integrity = backup_integrity and saved
    archive = backup / "legacy-update-receipt.json"
    legacy_archive_matches = (hashlib.sha256(_regular(archive)).hexdigest() == legacy_receipt_sha
                              if archive.exists() else False)
    failure = receipt.get("failure")
    failure = failure if isinstance(failure, dict) else {}
    failure_operation = failure.get("operation")
    failure_os_error = failure.get("os_error")
    if (
        failure_operation is None
        and failure_os_error is None
        and receipt.get("source_commit") != CURRENT_DIAGNOSTIC_RULES_SHA
    ):
        failure_operation = "legacy_unknown"
        sanitized_os_error = {"errno": None, "winerror": None}
    else:
        if (
            not isinstance(failure_operation, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", failure_operation)
        ):
            raise ReadbackBlocked("FAILURE_OPERATION_INVALID")
        if not isinstance(failure_os_error, dict):
            raise ReadbackBlocked("FAILURE_OS_ERROR_INVALID")
        sanitized_os_error = {}
        for key in ("errno", "winerror"):
            value = failure_os_error.get(key)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise ReadbackBlocked("FAILURE_OS_ERROR_INVALID")
            sanitized_os_error[key] = value
    result = {
        "result": "NOTERI_GATEWAY_FAILURE_READBACK",
        "receipt_sha256": receipt_sha,
        "receipt_origin": receipt_origin,
        "primary_receipt_sha256": primary_receipt_sha,
        "primary_receipt_source_commit": primary_receipt.get("source_commit"),
        "receipt_is_original": receipt_sha == legacy_receipt_sha,
        "receipt_result": receipt.get("result"),
        "source_commit": receipt.get("source_commit"),
        "phase": receipt.get("phase"),
        "failure_type": failure.get("type"),
        "failure_category": failure.get("category"),
        "failure_operation": failure_operation,
        "failure_os_error": sanitized_os_error,
        "mutation_started": receipt.get("mutation_started"),
        "rollback_attempted": receipt.get("rollback_attempted"),
        "rollback_succeeded": receipt.get("rollback_succeeded"),
        "manifest_version": manifest["version"],
        "manifest_sha256": manifest_sha,
        "manifest_is_original": manifest_sha == legacy_manifest_sha,
        "legacy_archive_matches": legacy_archive_matches,
        "backup_content_intact": backup_integrity,
        "all_previous_content": all(s["previous_content"] for s in states.values()),
        "all_desired_content": (all(s["desired_content"] for s in states.values())
                                if manifest["version"] == 2 else None),
        "managed_states": states,
        "journal_present": (root / "update-transaction.json").exists(),
        "managed_runtime_changed_by_readback": False,
    }
    if (_json(receipt_path)[1] != receipt_sha
            or _json(root / "update-receipt.json")[1] != primary_receipt_sha
            or _json(backup / "rollback-manifest.json")[1] != manifest_sha):
        raise ReadbackBlocked("EVIDENCE_CHANGED")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-legacy-receipt-sha256", required=True)
    parser.add_argument("--expected-legacy-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        report = inventory(ROOT, args.expected_legacy_receipt_sha256,
                           args.expected_legacy_manifest_sha256)
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ReadbackBlocked) else "HOST_READ_FAILED"
        print(json.dumps({"result": "NOTERI_GATEWAY_FAILURE_READBACK_BLOCKED", "reason": reason}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
