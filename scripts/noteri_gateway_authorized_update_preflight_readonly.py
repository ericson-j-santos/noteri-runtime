#!/usr/bin/env python3
"""Fixed-target read-only preflight for authorized Noteri Gateway update.

Does not execute the updater, create backups, alter receipts/journal/locks,
read credentials, or make any network request. Output is sanitized and bounded.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat

from noteri_ollama_recovery_preflight import source_sha

HOST = "noteri"
ROOT = Path(r"C:\dev\chatgpt-command-gateway")
CANDIDATE = "6f1dbb0a3c769f2c31ffa3b97ad57576f26ac27f"
CANDIDATE_GATEWAY_HASH = "20a34a44dc99f01a05e80bedced56517e5ac26f762c03412ca23c5cb940a4ccb"
CONFIRM = "INSPECT-NOTERI-GATEWAY-UPDATE-RECEIPT-READONLY"
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
BACKUP = re.compile(r"backup-[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\Z")
MAX_JSON = 1024 * 1024
GOOD_RECEIPTS = {"HOST_UPDATE_OK", "HOST_UPDATE_ALREADY_CURRENT_VERIFIED"}


class Blocked(RuntimeError):
    pass


def require_regular(path: Path) -> bytes:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or (info.st_file_attributes if hasattr(info, "st_file_attributes") else 0) & REPARSE:
            raise Blocked("PATH_REPARSE_OR_NOT_FILE")
        if not 1 <= info.st_size <= MAX_JSON:
            raise Blocked("FILE_SIZE_UNSAFE")
        payload = path.read_bytes()
        again = os.lstat(path)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            again.st_dev, again.st_ino, again.st_size, again.st_mtime_ns
        ) or len(payload) != info.st_size:
            raise Blocked("FILE_CHANGED_DURING_READ")
        return payload
    except (OSError, ValueError) as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("FILE_UNREADABLE") from exc


def require_directory(path: Path) -> None:
    try:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & REPARSE
        ):
            raise Blocked("PATH_REPARSE_OR_NOT_DIRECTORY")
    except (OSError, ValueError) as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("DIRECTORY_NOT_ATTESTED") from exc


def strict_object(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for k, v in pairs:
            if k in result:
                raise Blocked("DUPLICATE_JSON_KEYS")
            result[k] = v
        return result

    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(Blocked("JSON_CONSTANT_DENIED")),
        )
    except (ValueError, UnicodeError) as exc:
        raise Blocked("JSON_NOT_VALID") from exc
    if type(data) is not dict:
        raise Blocked("JSON_SHAPE_INVALID")
    return data


def read_stable_object(path: Path) -> tuple[dict, str]:
    first = require_regular(path)
    second = require_regular(path)
    if first != second:
        raise Blocked("RECEIPT_NOT_STABLE")
    return strict_object(first), hashlib.sha256(first).hexdigest()


def _safe_backup_root(backup_dir: object) -> tuple[bool, str]:
    if not isinstance(backup_dir, str) or not backup_dir:
        return False, "BACKUP_REF_ABSENT"
    path = Path(backup_dir)
    if not path.is_absolute() or not BACKUP.fullmatch(path.name):
        return False, "BACKUP_REF_INVALID"
    if os.path.normcase(os.path.abspath(path.parent)) != os.path.normcase(os.path.abspath(ROOT)):
        return False, "BACKUP_REF_OUTSIDE_ROOT"
    try:
        require_directory(path)
        manifest, _ = read_stable_object(path / "rollback-manifest.json")
    except Blocked:
        return False, "BACKUP_MANIFEST_UNVERIFIED"
    return isinstance(manifest.get("version"), int), "BACKUP_PRESENT" if isinstance(manifest.get("version"), int) else "BACKUP_MANIFEST_UNVERIFIED"


def inspect(root: Path = ROOT) -> dict:
    if (os.name != "nt" or socket.gethostname().casefold() != HOST
            or os.path.normcase(os.path.abspath(root))
               != os.path.normcase(os.path.abspath(ROOT))):
        raise Blocked("HOST_OR_ROOT_MISMATCH")
    require_directory(root)
    for section in ("bin", "config"):
        require_directory(root / section)
    gateway = root / "bin" / "command_gateway.py"
    policy = root / "config" / "policy.json"
    if gateway.is_symlink() or policy.is_symlink():
        raise Blocked("INSTALLED_SYMLINK")
    gateway_a, gateway_b = require_regular(gateway), require_regular(gateway)
    if gateway_a != gateway_b:
        raise Blocked("INSTALLED_GATEWAY_CHANGING")
    policy_data, policy_hash = read_stable_object(policy)
    gateway_sha = hashlib.sha256(gateway_a).hexdigest()
    installed_version = policy_data.get("rules_version")
    if not isinstance(installed_version, str):
        raise Blocked("POLICY_VERSION_NOT_ATTESTED")
    journal_present = os.path.lexists(root / "update-transaction.json")
    receipt_path = root / "update-receipt.json"
    receipt_present = os.path.lexists(receipt_path)
    result = {
        "result": "UPDATE_PREFLIGHT_BLOCKED",
        "host": "Noteri",
        "environment": "DEV",
        "authorized_candidate_sha": CANDIDATE,
        "installed_gateway_sha256": gateway_sha,
        "desired_gateway_sha256": CANDIDATE_GATEWAY_HASH,
        "candidate_already_installed": gateway_sha == CANDIDATE_GATEWAY_HASH,
        "installed_rules_version": installed_version,
        "policy_sha256": policy_hash,
        "journal_present": journal_present,
        "receipt_present": receipt_present,
        "mutation_performed": False,
        "backup_created": False,
        "apply_admitted": False,
    }
    if journal_present:
        result["reason"] = "PENDING_UPDATE_TRANSACTION_JOURNAL"
        return result
    if not receipt_present:
        result["reason"] = "UPDATE_RECEIPT_MISSING"
        return result
    receipt, sha = read_stable_object(receipt_path)
    status = receipt.get("result")
    result.update(
        receipt_result=status if isinstance(status, str) else "INVALID",
        receipt_sha256=sha,
        previous_source_sha=receipt.get("source_commit") if isinstance(
            receipt.get("source_commit"), str
        ) and re.fullmatch(r"[0-9a-f]{40}", receipt["source_commit"]) else None,
        mutation_started=receipt.get("mutation_started")
        if type(receipt.get("mutation_started")) is bool else None,
        rollback_succeeded=receipt.get("rollback_succeeded")
        if type(receipt.get("rollback_succeeded")) is bool else None,
    )
    backup_verified, reason = _safe_backup_root(receipt.get("backup_dir"))
    result["prior_backup_present"] = backup_verified
    if status in GOOD_RECEIPTS or (
        status == "HOST_UPDATE_BLOCKED"
        and receipt.get("mutation_started") is False
    ):
        result["result"] = "UPDATE_PREFLIGHT_READONLY"
        result["reason"] = "CONDITIONAL_INSTALL_REQUIRES_ACTIVE_CONTROLLER"
    else:
        result["reason"] = (
            "PREVIOUS_MUTATION_OR_ROLLBACK_NOT_RECONCILED"
            if receipt.get("mutation_started") is not False
            else "PRIOR_RECEIPT_UNRECOGNIZED"
        )
    # Historical result alone is NOT authority to start an installation.
    return result


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--confirm", required=True)
    a = p.parse_args()
    try:
        if (not ID.fullmatch(a.correlation_id)
                or not re.fullmatch(r"[0-9a-f]{40}", a.expected_head)
                or a.confirm != CONFIRM or a.candidate != CANDIDATE
                or source_sha(Path(__file__).resolve().parents[1]) != a.expected_head):
            raise Blocked("SOURCE_OR_REQUEST_NOT_ATTESTED")
        result = inspect()
        result["correlation_id"] = a.correlation_id
        print(json.dumps(result, sort_keys=True))
        return 0 if result["result"] == "UPDATE_PREFLIGHT_READONLY" else 2
    except (Blocked, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, Blocked) else "READBACK_UNAVAILABLE"
        print(json.dumps({"result": "UPDATE_PREFLIGHT_BLOCKED",
                          "reason": code,
                          "mutation_performed": False,
                          "apply_admitted": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
