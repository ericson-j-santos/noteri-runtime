#!/usr/bin/env python3
"""Fixed-target reversible archive of ONE pinned Noteri Gateway journal.

The CLI is CHECK ONLY: it cannot move anything. The internal commit method is
available solely to tests or to a future separately authorized, governed
capability. This module never installs a runtime or alters backup/receipt
contents, secrets, privileges or the Gateway service.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket

import noteri_gateway_journal_windows_metadata_readonly as metadata
import noteri_gateway_journal_binding_readonly as binding
import noteri_gateway_authorized_update_preflight_readonly as safe
from noteri_ollama_recovery_preflight import source_sha

ROOT = Path(r"C:\dev\chatgpt-command-gateway")
CONFIRM = "PREPARE-NOTERI-JOURNAL-ARCHIVE-ONLY-NO-MOVE"
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
TX = re.compile(r"[0-9a-f]{32}\Z")
MOVEFILE_WRITE_THROUGH = 0x8
API_CONTRACT = "noteri-journal-archive-one-v1"


class RecoveryBlocked(RuntimeError):
    pass


def require(value: bool, reason: str):
    if not value:
        raise RecoveryBlocked(reason)


def sha256(path: Path):
    raw = safe.require_regular(path)
    return hashlib.sha256(raw).hexdigest()


def find_historical_backup(root: Path) -> Path:
    """Find unique historical backup by pinned manifest, never a name from caller."""
    matches = []
    for child in root.iterdir():
        if child.name.startswith("backup-") and safe.BACKUP.fullmatch(child.name):
            safe.require_directory(child)
            candidate = child / "rollback-manifest.json"
            if os.path.lexists(candidate):
                value = sha256(candidate)
                if value == metadata.JOURNAL_MANIFEST_HASH:
                    matches.append(child)
    require(len(matches) == 1, "HISTORICAL_BACKUP_NOT_UNIQUE")
    return matches[0]


def locate(root: Path, *, journal_present: bool) -> tuple[Path, Path]:
    if journal_present:
        journal = root / "update-transaction.json"
        item, digest = safe.read_stable_object(journal)
        require(digest == metadata.JOURNAL_HASH, "JOURNAL_PIN_MISMATCH")
        require(type(item.get("transaction_id")) is str
                and TX.fullmatch(item["transaction_id"]) is not None,
                "JOURNAL_TRANSACTION_INVALID")
        folder = binding._backup(root, item.get("backup_dir"))
        require(sha256(folder / "rollback-manifest.json")
                == metadata.JOURNAL_MANIFEST_HASH,
                "HISTORICAL_MANIFEST_PIN_MISMATCH")
        archive = folder / ("recovered-update-transaction-"
                            + item["transaction_id"] + ".json")
        return journal, archive

    folder = find_historical_backup(root)
    candidates = [
        child for child in folder.iterdir()
        if child.name.startswith("recovered-update-transaction-")
        and child.name.endswith(".json")
    ]
    require(len(candidates) == 1, "RECOVERY_ARCHIVE_NOT_UNIQUE")
    archive = candidates[0]
    name = archive.name
    require(name.startswith("recovered-update-transaction-")
            and name.endswith(".json")
            and TX.fullmatch(name[len("recovered-update-transaction-"):-5])
            is not None, "RECOVERY_ARCHIVE_NAME_INVALID")
    item, digest = safe.read_stable_object(archive)
    require(digest == metadata.JOURNAL_HASH,
            "ARCHIVE_DIGEST_MISMATCH")
    require(archive.name == "recovered-update-transaction-"
            + str(item.get("transaction_id")) + ".json",
            "RECOVERY_ARCHIVE_TX_MISMATCH")
    return root / "update-transaction.json", archive


def verify_locked(root: Path, *, archived: bool, helper) -> dict:
    """Same full evidence gate before/after movement with exclusive lock held."""
    require(metadata._same_root(root)
            and os.name == "nt"
            and socket.gethostname().casefold() == "noteri",
            "HOST_OR_INSTALL_ROOT_MISMATCH")
    safe.require_directory(root)
    journal_path, archive = locate(root, journal_present=not archived)
    require(not os.path.lexists(journal_path) if archived
            else not os.path.lexists(archive),
            "JOURNAL_AND_ARCHIVE_CONFLICT")
    journal_source = archive if archived else journal_path
    record, journal_hash = safe.read_stable_object(journal_source)
    receipt, receipt_hash = safe.read_stable_object(root / "update-receipt.json")
    require(journal_hash == metadata.JOURNAL_HASH
            and receipt_hash == metadata.RECEIPT_HASH,
            "RECEIPT_OR_JOURNAL_PIN_CHANGED")
    require(record.get("version") == 1
            and record.get("source_commit") ==
            "58dcd4200f412a866278027ba9e433439a03f3b3"
            and receipt.get("result") == "HOST_UPDATE_OK"
            and receipt.get("source_commit") ==
            "11e2e86d0283e83247d8058d05bbabe3dd7cc2c2",
            "INCIDENT_IDENTITY_MISMATCH")
    require(record.get("transaction_id") != receipt.get("transaction_id")
            and record.get("backup_dir") != receipt.get("backup_dir"),
            "NOT_A_HISTORICAL_TRANSACTION")
    historical_content = binding._backup_state(root, record.get("backup_dir"))
    current_content = binding._backup_state(root, receipt.get("backup_dir"))
    count = len(binding.legacy.MANAGED)
    require(historical_content["backup_content_matches"] == count
            and historical_content["current_previous_matches"] == count
            and current_content["backup_content_matches"] == count
            and current_content["current_desired_matches"] == count,
            "BACKUP_CONTENT_OR_RUNTIME_DIVERGED")
    journal_acl = metadata._validate_file_security(helper, journal_source, None)
    receipt_acl = metadata._validate_file_security(
        helper, root / "update-receipt.json", None)
    historical_acl = metadata._folder_backup_state(
        root, helper, record["backup_dir"],
        metadata.JOURNAL_MANIFEST_HASH, "historical",
    )
    current_acl = metadata._folder_backup_state(
        root, helper, receipt["backup_dir"],
        metadata.RECEIPT_MANIFEST_HASH, "current",
    )
    require(historical_acl["backup_security_matches"] == count
            and historical_acl["current_security_matches"] == count
            and current_acl["backup_security_matches"] == count
            and current_acl["current_security_matches"] == count,
            "WINDOWS_SECURITY_DIVERGED")
    require(safe.read_stable_object(journal_source)[1] == metadata.JOURNAL_HASH
            and safe.read_stable_object(root / "update-receipt.json")[1]
            == metadata.RECEIPT_HASH,
            "READBACK_DRIFT")
    return {
        "contract": API_CONTRACT,
        "journal_sha256": journal_hash,
        "receipt_sha256": receipt_hash,
        "archive_name": archive.name,
        "journal_windows_metadata_sha256": journal_acl,
        "receipt_windows_metadata_sha256": receipt_acl,
        "backups_verified": 2,
        "managed_entries_verified": count,
        "archived": archived,
        "update_lock_held": True,
    }


def move_file_no_replace(source: Path, destination: Path):
    """One fixed-file same-volume Win32 move, no overwrite, no delete."""
    require(not os.path.lexists(destination), "ARCHIVE_ALREADY_EXISTS")
    require(source.parent.drive.casefold() == destination.parent.drive.casefold(),
            "CROSS_VOLUME_MOVE_FORBIDDEN")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel.MoveFileExW
    move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    move.restype = ctypes.c_int
    if not move(str(source), str(destination), MOVEFILE_WRITE_THROUGH):
        raise RecoveryBlocked("WIN32_MOVE_FAILED")


def recover(root: Path = ROOT, *, apply: bool = False,
            mover=move_file_no_replace, helper_loader=None) -> dict:
    """Check-only by default. apply=True NOT exposed through public CLI."""
    require(metadata._same_root(root)
            and os.name == "nt"
            and socket.gethostname().casefold() == "noteri",
            "HOST_OR_INSTALL_ROOT_MISMATCH")
    safe.require_directory(root)
    helper = (helper_loader or metadata._fixed_helper)()
    with metadata.existing_exclusive_update_lock(root):
        journal = root / "update-transaction.json"
        historical = os.path.lexists(journal)
        first = verify_locked(root, archived=not historical, helper=helper)
        second = verify_locked(root, archived=not historical, helper=helper)
        require(first == second, "PRECHECK_CHANGED")
        if not historical:
            return {
                "result": "JOURNAL_ALREADY_ARCHIVED_VERIFIED",
                "mutation_performed": False, "replayed": True, **second,
            }
        if not apply:
            return {
                "result": "JOURNAL_ARCHIVE_PREPARED_READONLY",
                "mutation_performed": False,
                "apply_authorized": False, **second,
            }
        _, archive = locate(root, journal_present=True)
        moved = False
        try:
            mover(journal, archive)
            moved = True
            require(not os.path.lexists(journal) and os.path.lexists(archive),
                    "JOURNAL_MOVE_POSTCONDITION_FAILED")
            after = verify_locked(root, archived=True, helper=helper)
            require(after["journal_windows_metadata_sha256"] ==
                    first["journal_windows_metadata_sha256"],
                    "MOVED_JOURNAL_SECURITY_CHANGED")
            require(after["receipt_windows_metadata_sha256"] ==
                    first["receipt_windows_metadata_sha256"],
                    "PRIMARY_RECEIPT_SECURITY_CHANGED")
            return {
                "result": "JOURNAL_ARCHIVED_VERIFIED",
                "mutation_performed": True, "replayed": False,
                **after,
            }
        except Exception as cause:
            if not moved:
                raise RecoveryBlocked("MOVE_NOT_COMPLETED_OR_UNKNOWN") from cause
            try:
                require(not os.path.lexists(journal) and os.path.lexists(archive),
                        "ROLLBACK_PREDICATE_FAILED")
                mover(archive, journal)
                require(os.path.lexists(journal) and not os.path.lexists(archive),
                        "ROLLBACK_MOVE_POSTCONDITION_FAILED")
                recovered = verify_locked(root, archived=False, helper=helper)
                require(recovered == first, "ROLLBACK_READBACK_DIVERGENT")
            except Exception as rollback_error:
                raise RecoveryBlocked("JOURNAL_RECOVERY_ROLLBACK_NOT_PROVEN") from rollback_error
            raise RecoveryBlocked("POST_MOVE_FAILED_ROLLED_BACK") from cause


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--confirm", required=True)
    ns = p.parse_args()
    try:
        require(HEAD.fullmatch(ns.expected_head) is not None
                and ID.fullmatch(ns.correlation_id) is not None
                and ns.confirm == CONFIRM
                and source_sha(Path(__file__).resolve().parents[1]) == ns.expected_head,
                "SOURCE_OR_REQUEST_NOT_ATTESTED")
        report = recover(apply=False)
        report["correlation_id"] = ns.correlation_id
        print(json.dumps(report, sort_keys=True))
        return 0
    except (RecoveryBlocked, metadata.Blocked, safe.Blocked,
            binding.Blocked, OSError, ValueError) as exc:
        reason = (str(exc) if isinstance(
            exc, (RecoveryBlocked, metadata.Blocked, safe.Blocked,
                  binding.Blocked)) else "RECOVERY_PRECHECK_UNAVAILABLE")
        print(json.dumps({
            "result": "JOURNAL_ARCHIVE_PRECHECK_BLOCKED",
            "reason": reason,
            "mutation_performed": False, "apply_authorized": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
