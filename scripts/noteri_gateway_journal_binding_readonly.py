#!/usr/bin/env python3
"""Read-only, fixed-incident transaction/journal/rollback integrity inventory.

The observed journal must never be deleted, replaced or archived here. This
script does not acquire locks, execute the updater, open secrets or mutate the
installed Command Gateway. It never treats content-only checks as proof of
Windows ACL, owner, alternate streams, concurrency or authorization to move.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket

import noteri_gateway_authorized_update_preflight_readonly as safe
import noteri_gateway_failure_readback as legacy
from noteri_ollama_recovery_preflight import source_sha

ROOT = Path(r"C:\dev\chatgpt-command-gateway")
CONFIRM = "AUDIT-NOTERI-GATEWAY-JOURNAL-BINDING-READONLY"
HEAD = re.compile(r"[0-9a-f]{40}\Z")
TX = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
GOOD_RECEIPTS = {"HOST_UPDATE_OK", "HOST_UPDATE_ALREADY_CURRENT_VERIFIED"}


class Blocked(RuntimeError):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Blocked(reason)


def _strict(path: Path) -> tuple[dict, str]:
    return safe.read_stable_object(path)


def _backup(root: Path, value: object) -> Path:
    _require(type(value) is str, "BACKUP_REFERENCE_INVALID")
    path = Path(value)
    _require(path.is_absolute() and safe.BACKUP.fullmatch(path.name) is not None,
             "BACKUP_REFERENCE_INVALID")
    _require(
        os.path.normcase(os.path.abspath(path.parent))
        == os.path.normcase(os.path.abspath(root)),
        "BACKUP_REFERENCE_OUTSIDE_INSTALL_ROOT",
    )
    safe.require_directory(path)
    safe.require_directory(path / "files")
    return path


def _matched(path: Path, digest: object, size: object) -> bool:
    _require(type(digest) is str and SHA.fullmatch(digest) is not None,
             "MANIFEST_DIGEST_INVALID")
    _require(type(size) is int and 0 <= size <= 1024 * 1024,
             "MANIFEST_SIZE_INVALID")
    if not os.path.lexists(path):
        return False
    try:
        data = safe.require_regular(path)
    except safe.Blocked:
        raise Blocked("MANAGED_FILE_UNSAFE") from None
    return len(data) == size and hashlib.sha256(data).hexdigest() == digest


def _backup_state(root: Path, value: object) -> dict:
    path = _backup(root, value)
    manifest, digest = _strict(path / "rollback-manifest.json")
    entries = manifest.get("entries")
    _require(manifest.get("version") == 2 and type(entries) is dict,
             "BACKUP_MANIFEST_NOT_V2")
    _require(set(entries) == legacy.MANAGED, "BACKUP_MANAGED_SET_MISMATCH")
    _require(
        os.path.normcase(str(manifest.get("install_root", "")))
        == os.path.normcase(str(root)),
        "BACKUP_INSTALL_ROOT_MISMATCH",
    )
    previous_matches = 0
    desired_matches = 0
    backup_matches = 0
    for rel in sorted(legacy.MANAGED):
        item = entries[rel]
        _require(type(item) is dict and type(item.get("existed")) is bool,
                 "BACKUP_ENTRY_INVALID")
        current_path = root.joinpath(*rel.split("/"))
        saved_path = path / "files" / rel
        if item["existed"]:
            backup_ok = _matched(saved_path, item.get("previous_sha256"),
                                 item.get("previous_size"))
            previous_ok = _matched(current_path, item.get("previous_sha256"),
                                   item.get("previous_size"))
        else:
            backup_ok = not os.path.lexists(saved_path)
            previous_ok = not os.path.lexists(current_path)
        desired_ok = _matched(current_path, item.get("desired_sha256"),
                              item.get("desired_size"))
        backup_matches += int(backup_ok)
        previous_matches += int(previous_ok)
        desired_matches += int(desired_ok)
    # Compare manifest contents a second time after all managed reads.
    _require(_strict(path / "rollback-manifest.json")[1] == digest,
             "BACKUP_CHANGED_DURING_INSPECTION")
    return {
        "manifest_sha256": digest,
        "version": manifest["version"],
        "managed_count": len(legacy.MANAGED),
        "backup_content_matches": backup_matches,
        "current_previous_matches": previous_matches,
        "current_desired_matches": desired_matches,
        "windows_security_metadata_verified": False,
    }


def inspect(root: Path = ROOT) -> dict:
    _require(os.name == "nt" and socket.gethostname().casefold() == "noteri",
             "HOST_NOTERI_REQUIRED")
    _require(
        os.path.normcase(os.path.abspath(root))
        == os.path.normcase(os.path.abspath(ROOT)),
        "ROOT_INVALID",
    )
    safe.require_directory(root)
    receipt, receipt_sha = _strict(root / "update-receipt.json")
    journal, journal_sha = _strict(root / "update-transaction.json")

    _require(journal.get("version") == 1, "JOURNAL_VERSION_INVALID")
    _require(type(journal.get("transaction_id")) is str and
             TX.fullmatch(journal["transaction_id"]) is not None,
             "JOURNAL_TX_INVALID")
    _require(type(journal.get("source_commit")) is str and
             HEAD.fullmatch(journal["source_commit"]) is not None,
             "JOURNAL_SOURCE_INVALID")
    _require(type(receipt.get("source_commit")) is str and
             HEAD.fullmatch(receipt["source_commit"]) is not None,
             "RECEIPT_SOURCE_INVALID")
    journal_backup = _backup_state(root, journal.get("backup_dir"))
    same_transaction = (
        journal.get("transaction_id") == receipt.get("transaction_id")
    )
    same_source = journal["source_commit"] == receipt["source_commit"]
    same_backup = (
        type(receipt.get("backup_dir")) is str and
        os.path.normcase(str(journal["backup_dir"]))
        == os.path.normcase(str(receipt["backup_dir"]))
    )
    receipt_backup = (
        journal_backup if same_backup else _backup_state(root, receipt.get("backup_dir"))
    )
    # Re-read source metadata after looking at both on-disk backups.
    _require(_strict(root / "update-receipt.json")[1] == receipt_sha,
             "RECEIPT_CHANGED_DURING_INSPECTION")
    _require(_strict(root / "update-transaction.json")[1] == journal_sha,
             "JOURNAL_CHANGED_DURING_INSPECTION")
    full_journal_backup = (
        journal_backup["backup_content_matches"]
        == journal_backup["managed_count"]
    )
    full_receipt_backup = (
        receipt_backup["backup_content_matches"]
        == receipt_backup["managed_count"]
    )
    receipt_good = receipt.get("result") in GOOD_RECEIPTS
    is_bound = same_transaction and same_source and same_backup
    reason = (
        "JOURNAL_AND_RECEIPT_SAME_TRANSACTION"
        if is_bound else
        "JOURNAL_DIFFERS_FROM_CURRENT_SUCCESS_RECEIPT"
        if receipt_good else "JOURNAL_RECEIPT_IDENTITY_DIVERGED"
    )
    return {
        "result": "GATEWAY_JOURNAL_BINDING_READONLY",
        "host": "Noteri", "environment": "DEV",
        "journal_sha256": journal_sha,
        "receipt_sha256": receipt_sha,
        "journal_source_commit": journal["source_commit"],
        "receipt_source_commit": receipt["source_commit"],
        "receipt_result": receipt.get("result") if isinstance(receipt.get("result"), str) else "INVALID",
        "same_transaction_id": same_transaction,
        "same_source_commit": same_source,
        "same_backup_directory": same_backup,
        "journal_backup": journal_backup,
        "receipt_backup": receipt_backup,
        "journal_backup_content_complete": full_journal_backup,
        "receipt_backup_content_complete": full_receipt_backup,
        "receipt_current_desired_content_complete": (
            receipt_backup["current_desired_matches"]
            == receipt_backup["managed_count"]
        ),
        "identity_classification": reason,
        "rollback_authorized": False,
        "journal_move_authorized": False,
        "windows_security_metadata_verified": False,
        "state_changed": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--confirm", required=True)
    a = p.parse_args()
    try:
        if (
            not HEAD.fullmatch(a.expected_head) or
            not ID.fullmatch(a.correlation_id) or a.confirm != CONFIRM or
            source_sha(Path(__file__).resolve().parents[1]) != a.expected_head
        ):
            raise Blocked("SOURCE_OR_REQUEST_NOT_ATTESTED")
        out = inspect()
        out["correlation_id"] = a.correlation_id
        print(json.dumps(out, sort_keys=True))
        return 0
    except (Blocked, safe.Blocked, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, (Blocked, safe.Blocked)) else "READ_ONLY_AUDIT_ERROR"
        print(json.dumps({"result": "GATEWAY_JOURNAL_BINDING_BLOCKED",
                          "reason": code, "state_changed": False,
                          "journal_move_authorized": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
