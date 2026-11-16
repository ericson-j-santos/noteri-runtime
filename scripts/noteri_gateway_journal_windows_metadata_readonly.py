#!/usr/bin/env python3
"""Read-only Win32 security/lease audit for one pinned Noteri Gateway journal.

No updater, download, backup mutation, process stop or journal movement.
The lock is OPEN_EXISTING + GENERIC_READ + share=0, never O_CREAT.
Sensitive owner/group SIDs, DACL/ACEs and alternate-stream names are not emitted.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

import noteri_gateway_journal_binding_readonly as binding
import noteri_gateway_authorized_update_preflight_readonly as safe
from noteri_ollama_recovery_preflight import source_sha

ROOT = Path(r"C:\dev\chatgpt-command-gateway")
HELPER = Path(
    r"C:\dev\chatgpt-workers\wt-chat-rules213-gateway-validator-6f1-20261115"
    r"\scripts\install_command_gateway_host.py"
)
HELPER_HASH = "4b2c200680de7e0db6bd44905a246d7e1773b36d0f516d9756046e758827e35a"
JOURNAL_HASH = "757ec16e15cf260b24438ab5e7f674eb0b15b6f0a7318dc27aeed6cfbf76c8d0"
RECEIPT_HASH = "def5a5fc7f7748a61adac626420b3305aeb174f8db6332e48f94ca362393c741"
JOURNAL_MANIFEST_HASH = "be7e55cbf943ce624df2528f99358140d304abe5a5b1888e19183166afc53be1"
RECEIPT_MANIFEST_HASH = "f0e6b403c54cdfd005c22395660fb5a0871393c5d4d8babc5936a7aadc45164c"
CONFIRM = "AUDIT-NOTERI-GATEWAY-JOURNAL-WINDOWS-METADATA-READONLY"
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class Blocked(RuntimeError):
    pass


def _require(condition: bool, reason: str):
    if not condition:
        raise Blocked(reason)


def _same_root(root: Path) -> bool:
    return (os.path.normcase(os.path.abspath(root))
            == os.path.normcase(os.path.abspath(ROOT)))


def _fixed_helper():
    """Load the already materialized, exact approved Rules helper after SHA pin."""
    try:
        raw = safe.require_regular(HELPER)
    except safe.Blocked as exc:
        raise Blocked("PINNED_METADATA_HELPER_MISSING") from exc
    _require(hashlib.sha256(raw).hexdigest() == HELPER_HASH,
             "PINNED_METADATA_HELPER_HASH_INVALID")
    spec = importlib.util.spec_from_file_location("_rules213_windows_metadata", HELPER)
    _require(spec is not None and spec.loader is not None,
             "PINNED_METADATA_HELPER_IMPORT_BLOCKED")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise Blocked("PINNED_METADATA_HELPER_IMPORT_BLOCKED") from exc
    _require(hashlib.sha256(safe.require_regular(HELPER)).hexdigest() == HELPER_HASH,
             "PINNED_METADATA_HELPER_CHANGED")
    return module


def _validate_file_security(helper, path: Path, expected: dict | None,
                            *, require_no_streams: bool = False):
    try:
        first = helper._windows_persisted_file_state(path)
        second = helper._windows_persisted_file_state(path)
        _require(first == second, "WINDOWS_FILE_METADATA_CHANGED")
        if expected is not None:
            helper._validate_windows_persisted_state(expected, path.name)
            _require(helper._windows_persisted_state_equivalent(expected, first),
                     "WINDOWS_METADATA_MISMATCH")
        if require_no_streams:
            _require(first.get("streams") == [], "NEW_FILE_HAS_ALTERNATE_DATA_STREAMS")
        # Stable metadata hash (not raw owner, group, DACL or ADS names).
        return hashlib.sha256(
            json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except Blocked:
        raise
    except Exception as exc:
        raise Blocked("WINDOWS_FILE_METADATA_UNAVAILABLE") from exc


def _validate_directory_security(helper, path: Path):
    safe.require_directory(path)
    try:
        one = helper._windows_get_security_descriptor(path)
        two = helper._windows_get_security_descriptor(path)
        _require(one == two, "WINDOWS_DIRECTORY_DESCRIPTOR_CHANGED")
        return hashlib.sha256(one).hexdigest()
    except Blocked:
        raise
    except Exception as exc:
        raise Blocked("WINDOWS_DIRECTORY_METADATA_UNAVAILABLE") from exc


@contextmanager
def existing_exclusive_update_lock(root: Path):
    """Hold the same update.lock with share=0. Never creates/changes the lock."""
    path = root / "update.lock"
    try:
        before = os.lstat(path)
        _require(stat.S_ISREG(before.st_mode)
                 and not bool(getattr(before, "st_file_attributes", 0) & 0x400),
                 "UPDATE_LOCK_INVALID")
    except (OSError, ValueError) as exc:
        raise Blocked("UPDATE_LOCK_MISSING_OR_INVALID") from exc
    _require(os.name == "nt", "WINDOWS_REQUIRED")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_ = kernel.CreateFileW
    open_.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    open_.restype = ctypes.c_void_p
    handle = open_(
        str(path), GENERIC_READ, 0, None, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, None,
    )
    if handle is None or handle == INVALID_HANDLE_VALUE:
        raise Blocked("UPDATE_LOCK_BUSY_OR_ACCESS_DENIED")
    try:
        after = os.lstat(path)
        _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                 "UPDATE_LOCK_CHANGED")
        yield
    finally:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle(ctypes.c_void_p(handle))


def _folder_backup_state(root: Path, helper, backup_value: object, manifest_hash: str,
                         mode: str) -> dict:
    backup = binding._backup(root, backup_value)
    manifest_path = backup / "rollback-manifest.json"
    manifest, actual_hash = safe.read_stable_object(manifest_path)
    _require(actual_hash == manifest_hash, "BACKUP_MANIFEST_HASH_MISMATCH")
    entries = manifest.get("entries")
    _require(manifest.get("version") == 2
             and isinstance(entries, dict)
             and set(entries) == binding.legacy.MANAGED,
             "BACKUP_MANIFEST_INVALID")
    _validate_directory_security(helper, backup)
    _validate_directory_security(helper, backup / "files")
    _validate_file_security(helper, manifest_path, None)
    backup_valid = 0
    active_metadata_valid = 0
    newly_created_without_streams = 0
    historical_absent_verified = 0
    for rel in sorted(binding.legacy.MANAGED):
        record = entries[rel]
        _require(isinstance(record, dict) and
                 type(record.get("existed")) is bool,
                 "BACKUP_ENTRY_INVALID")
        saved = backup / "files" / rel
        current = root.joinpath(*rel.split("/"))
        if record["existed"]:
            expected = record.get("previous_windows_state")
            _require(isinstance(expected, dict), "WINDOWS_ROLLBACK_STATE_MISSING")
            _require(binding._matched(saved, record.get("previous_sha256"),
                                     record.get("previous_size")),
                     "SAVED_FILE_CONTENT_DIVERGED")
            _validate_file_security(helper, saved, expected)
            backup_valid += 1
        else:
            _require(record.get("previous_windows_state") is None,
                     "NONEXISTENT_FILE_HAS_PREVIOUS_SECURITY")
            _require(not os.path.lexists(saved),
                     "NONEXISTENT_BACKUP_FILE_PRESENT")
            backup_valid += 1

        if mode == "historical":
            if record["existed"]:
                _require(binding._matched(current, record.get("previous_sha256"),
                                         record.get("previous_size")),
                         "HISTORICAL_RUNTIME_CONTENT_DIVERGED")
                _validate_file_security(helper, current, expected)
                active_metadata_valid += 1
            else:
                _require(not os.path.lexists(current),
                         "HISTORICAL_ABSENT_FILE_PRESENT")
                historical_absent_verified += 1
                active_metadata_valid += 1
        elif mode == "current":
            _require(binding._matched(current, record.get("desired_sha256"),
                                     record.get("desired_size")),
                     "CURRENT_RUNTIME_CONTENT_DIVERGED")
            if record["existed"]:
                _validate_file_security(helper, current, expected)
            else:
                # Brand-new file has no preserved owner/DACL baseline.
                # Inventory it twice and reject unexpected ADS; do NOT label
                # its owner/group/DACL as equivalent to a nonexistent state.
                _validate_file_security(helper, current, None,
                                        require_no_streams=True)
                newly_created_without_streams += 1
            active_metadata_valid += 1
        else:
            raise Blocked("INVALID_AUDIT_MODE")
    _require(safe.read_stable_object(manifest_path)[1] == manifest_hash,
             "BACKUP_MANIFEST_CHANGED")
    return {
        "manifest_sha256": actual_hash,
        "managed_count": len(entries),
        "backup_security_matches": backup_valid,
        "current_security_matches": active_metadata_valid,
        "new_files_without_ads": newly_created_without_streams,
        "historical_absences_verified": historical_absent_verified,
        "directory_descriptor_stable": True,
    }


def inspect(root: Path = ROOT, *, helper_loader=_fixed_helper) -> dict:
    _require(os.name == "nt" and socket.gethostname().casefold() == "noteri"
             and _same_root(root), "HOST_OR_INSTALL_ROOT_INVALID")
    safe.require_directory(root)
    helper = helper_loader()
    with existing_exclusive_update_lock(root):
        journal, journal_digest = safe.read_stable_object(root / "update-transaction.json")
        receipt, receipt_digest = safe.read_stable_object(root / "update-receipt.json")
        _require(journal_digest == JOURNAL_HASH and receipt_digest == RECEIPT_HASH,
                 "JOURNAL_OR_RECEIPT_CHANGED")
        evidence = binding.inspect(root)
        _require(evidence["identity_classification"]
                 == "JOURNAL_DIFFERS_FROM_CURRENT_SUCCESS_RECEIPT",
                 "JOURNAL_IDENTITY_UNEXPECTED")
        _require(evidence["journal_backup_content_complete"]
                 and evidence["receipt_backup_content_complete"]
                 and evidence["receipt_current_desired_content_complete"],
                 "CONTENT_BASELINE_NOT_INTACT")
        _validate_file_security(helper, root / "update-transaction.json", None)
        _validate_file_security(helper, root / "update-receipt.json", None)
        historical = _folder_backup_state(
            root, helper, journal.get("backup_dir"), JOURNAL_MANIFEST_HASH, "historical",
        )
        current = _folder_backup_state(
            root, helper, receipt.get("backup_dir"), RECEIPT_MANIFEST_HASH, "current",
        )
        _require(safe.read_stable_object(root / "update-transaction.json")[1] == JOURNAL_HASH
                 and safe.read_stable_object(root / "update-receipt.json")[1] == RECEIPT_HASH,
                 "EVIDENCE_CHANGED_UNDER_LOCK")
        return {
            "result": "JOURNAL_WINDOWS_METADATA_AUDIT_OK",
            "journal_sha256": JOURNAL_HASH,
            "receipt_sha256": RECEIPT_HASH,
            "rollback_historical": historical,
            "rollback_current": current,
            "exclusive_lock_held_for_audit": True,
            "mutation_performed": False,
            "recovery_authorized": False,
            "journal_move_authorized": False,
            "archive_destination_tested": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        _require(HEAD.fullmatch(args.expected_head) is not None
                 and ID.fullmatch(args.correlation_id) is not None
                 and args.confirm == CONFIRM
                 and source_sha(Path(__file__).resolve().parents[1]) == args.expected_head,
                 "SOURCE_OR_REQUEST_UNATTESTED")
        result = inspect()
        result["correlation_id"] = args.correlation_id
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, safe.Blocked, binding.Blocked, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, (Blocked, safe.Blocked, binding.Blocked)) else "WIN32_AUDIT_BLOCKED"
        print(json.dumps({
            "result": "JOURNAL_WINDOWS_METADATA_AUDIT_BLOCKED",
            "reason": reason, "mutation_performed": False,
            "recovery_authorized": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
