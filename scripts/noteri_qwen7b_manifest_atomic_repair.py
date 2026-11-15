#!/usr/bin/env python3
"""Reparo governado e reversível, SOMENTE do manifesto Qwen2.5 Coder 7B DEV.

--mode status é somente leitura. --mode apply é Risk2 e exige autorização
específica do proprietário, Session Launcher, Gateway, worktree e SHA atual.
Não baixa pesos, não instala, não altera o binário nem inicia o Ollama.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
from pathlib import Path

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import path_safe, source_sha
from noteri_ollama_tcp_table_probe import inspect_windows_listener
from noteri_watchdog_readonly_inventory import ollama_process_state
from noteri_qwen7b_official_manifest_compare import (
    EXPECTED_LOCAL_SHA, EXPECTED_OFFICIAL_SHA256, MAX_MANIFEST_BYTES,
    compare, fetch_official_manifest,
)

ACTION = "noteri.qwen7b.manifest.reconcile.v1"
CONFIRM_APPLY = "APPROVE-NOTERI-QWEN7B-MANIFEST-ONLY-DEV"
IDEMPOTENCY = "noteri:qwen7b:manifest-4aaba1-to-dae161:dev:v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")


class RepairBlocked(RuntimeError):
    pass


def require(test: bool, reason: str) -> None:
    if not test:
        raise RepairBlocked(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixed_paths(home: Path) -> tuple[Path, Path, Path]:
    store = home / ".ollama" / "models"
    manifest = (store / "manifests" / "registry.ollama.ai"
                / "library" / "qwen2.5-coder" / "7b")
    backup = manifest.with_name("7b.reqsys-backup-" + EXPECTED_LOCAL_SHA[:12])
    lock = manifest.with_name("7b.reqsys-reconcile.lock")
    for path in (store, manifest, backup, lock):
        require(path_safe(path, home), "UNSAFE_MODEL_PATH")
    return manifest, backup, lock


def inspect_state(manifest: Path, backup: Path) -> dict[str, object]:
    require(manifest.is_file() and not manifest.is_symlink(), "MANIFEST_INVALID")
    require(0 < manifest.stat().st_size <= MAX_MANIFEST_BYTES, "MANIFEST_SIZE_INVALID")
    observed = sha(manifest.read_bytes())
    backup_sha = None
    if backup.exists() or backup.is_symlink():
        require(backup.is_file() and not backup.is_symlink()
                and 0 < backup.stat().st_size <= MAX_MANIFEST_BYTES,
                "BACKUP_INVALID")
        backup_sha = sha(backup.read_bytes())
        require(backup_sha == EXPECTED_LOCAL_SHA, "BACKUP_DIGEST_INVALID")
    return {
        "manifest_sha256": observed, "backup_sha256": backup_sha,
        "official_manifest_installed": observed == EXPECTED_OFFICIAL_SHA256,
        "original_manifest_installed": observed == EXPECTED_LOCAL_SHA,
        "state_changed": False, "model_started": False,
    }


def write_exclusive(path: Path, data: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise RepairBlocked("EXCLUSIVE_WRITE_FAILED") from None
    require(path.is_file() and sha(path.read_bytes()) == sha(data),
            "STAGED_READBACK_FAILED")


def replace_transaction(manifest: Path, backup: Path, lock: Path,
                        official: bytes) -> dict[str, object]:
    """Real transaction with exclusive backup, atomic swap and verified rollback."""
    require(sha(official) == EXPECTED_OFFICIAL_SHA256, "OFFICIAL_BYTES_MISMATCH")
    require(manifest.is_file() and not manifest.is_symlink(), "MANIFEST_UNAVAILABLE")
    previous = manifest.read_bytes()
    before_hash = sha(previous)
    if before_hash == EXPECTED_OFFICIAL_SHA256:
        status = inspect_state(manifest, backup)
        require(status["backup_sha256"] == EXPECTED_LOCAL_SHA,
                "OFFICIAL_ALREADY_PRESENT_WITHOUT_BACKUP")
        return {"result": "MANIFEST_ALREADY_RECONCILED",
                "state_changed": False, "backup_verified": True}
    require(before_hash == EXPECTED_LOCAL_SHA, "MANIFEST_CHANGED")
    require(not lock.exists() and not lock.is_symlink(), "EXCLUSIVE_LOCK_BUSY")
    write_exclusive(lock, b"QWEN7B-MANIFEST-RECONCILE-DEV\n")
    stage = manifest.with_name("7b.reqsys-reconcile-stage")
    replaced = False
    stage_created = False
    try:
        require(not stage.exists() and not stage.is_symlink(), "STAGE_CONFLICT")
        if backup.exists() or backup.is_symlink():
            old = inspect_state(manifest, backup)
            require(old["backup_sha256"] == EXPECTED_LOCAL_SHA,
                    "BACKUP_CONFLICT")
        else:
            write_exclusive(backup, previous)
        require(sha(manifest.read_bytes()) == EXPECTED_LOCAL_SHA,
                "MANIFEST_RACE")
        require(ollama_process_state() == "ABSENT"
                and inspect_windows_listener() == "ABSENT",
                "OLLAMA_NOT_QUIESCENT")
        write_exclusive(stage, official)
        stage_created = True
        os.replace(stage, manifest)
        replaced = True
        require(sha(manifest.read_bytes()) == EXPECTED_OFFICIAL_SHA256,
                "OFFICIAL_READBACK_FAILED")
        require(sha(backup.read_bytes()) == EXPECTED_LOCAL_SHA,
                "BACKUP_READBACK_FAILED")
        return {"result": "MANIFEST_ATOMICALLY_RECONCILED",
                "state_changed": True, "backup_verified": True,
                "official_manifest_sha256": EXPECTED_OFFICIAL_SHA256,
                "original_manifest_sha256": EXPECTED_LOCAL_SHA,
                "model_started": False, "model_downloaded": False}
    except (OSError, RepairBlocked) as err:
        if replaced:
            try:
                restore = manifest.with_name("7b.reqsys-reconcile-restore")
                require(not restore.exists() and not restore.is_symlink(),
                        "RESTORE_STAGE_CONFLICT")
                write_exclusive(restore, previous)
                os.replace(restore, manifest)
            except (OSError, RepairBlocked):
                return {"result": "BLOCKED_ROLLBACK_FAILED",
                        "state_changed": True, "backup_verified": False}
        restored = manifest.is_file() and sha(manifest.read_bytes()) == EXPECTED_LOCAL_SHA
        return {"result": "BLOCKED_ROLLED_BACK" if restored else "BLOCKED_ROLLBACK_FAILED",
                "reason": str(err) if isinstance(err, RepairBlocked) else "IO_FAILURE",
                "state_changed": not restored, "backup_verified": (
                    backup.is_file() and sha(backup.read_bytes()) == EXPECTED_LOCAL_SHA)}
    finally:
        try:
            if stage_created and stage.is_file() and not stage.is_symlink():
                stage.unlink()
            lock.unlink()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("status", "apply"), required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--action", default="")
    parser.add_argument("--idempotency-key", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        require(bool(SHA40.fullmatch(args.source_sha))
                and bool(CORRELATION.fullmatch(args.correlation_id))
                and socket.gethostname().casefold() == "noteri"
                and os.name == "nt" and watchdog.runtime_profile() == "NORMAL"
                and source_sha(root) == args.source_sha,
                "SOURCE_IDENTITY_MISMATCH")
        home = Path.home()
        configured = os.environ.get("OLLAMA_MODELS", "")
        require(not configured or Path(configured) == home / ".ollama" / "models",
                "CUSTOM_MODEL_STORE")
        manifest, backup, lock = fixed_paths(home)
        if args.mode == "status":
            receipt = {"result": "NOTERI_QWEN7B_MANIFEST_STATUS_READONLY",
                       **inspect_state(manifest, backup)}
        else:
            require(args.action == ACTION and args.idempotency_key == IDEMPOTENCY
                    and args.confirm == CONFIRM_APPLY,
                    "SPECIFIC_OWNER_APPROVAL_REQUIRED")
            state = inspect_state(manifest, backup)
            require(state["manifest_sha256"] in
                    (EXPECTED_LOCAL_SHA, EXPECTED_OFFICIAL_SHA256),
                    "UNEXPECTED_MANIFEST")
            if state["official_manifest_installed"]:
                require(state["backup_sha256"] == EXPECTED_LOCAL_SHA,
                        "OFFICIAL_WITHOUT_APPROVED_BACKUP")
                receipt = {"result": "MANIFEST_ALREADY_RECONCILED",
                           "state_changed": False, "backup_verified": True}
            else:
                require(ollama_process_state() == "ABSENT"
                        and inspect_windows_listener() == "ABSENT",
                        "OLLAMA_NOT_QUIESCENT")
                official = fetch_official_manifest()
                candidate = compare(manifest.read_bytes(), official,
                                    home / ".ollama" / "models",
                                    verify_blob_sha256=True)
                require(candidate["full_official_blob_hash_verified"]
                        and candidate["official_blobs_size_missing"] == 0
                        and candidate["local_equals_expected_preflight"],
                        "OFFICIAL_BLOBS_NOT_ATTESTED")
                receipt = replace_transaction(manifest, backup, lock, official)
        receipt["correlation_id"] = args.correlation_id
        receipt["source_sha"] = args.source_sha
        print(json.dumps(receipt, sort_keys=True))
        return 0 if receipt["result"] in (
            "NOTERI_QWEN7B_MANIFEST_STATUS_READONLY",
            "MANIFEST_ALREADY_RECONCILED",
            "MANIFEST_ATOMICALLY_RECONCILED",
        ) else 2
    except (RepairBlocked, OSError) as err:
        print(json.dumps({
            "result": "QWEN7B_MANIFEST_RECONCILE_BLOCKED",
            "reason": str(err) if isinstance(err, RepairBlocked) else "IO_FAILURE",
            "state_changed": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
