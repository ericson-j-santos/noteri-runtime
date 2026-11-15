#!/usr/bin/env python3
"""Capability fixa para iniciar o Ollama existente, apenas no Noteri DEV.

Não executa downloads, instaladores, CLI arbitrário ou privilégios elevados.
Somente dentro de Session Launcher + Command Gateway Risk2 aprovado.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import (
    CONFIRM as PREFLIGHT_CONFIRM, plan as preflight_plan, path_safe,
)
from noteri_ollama_tcp_table_probe import inspect_windows_listener
from noteri_watchdog_readonly_inventory import ollama_process_state, read_model_tags

SCHEMA = 1
ACTION = "noteri.ollama.start.dev.v1"
ENVIRONMENT = "DEV"
CONFIRM = "START-EXISTING-OLLAMA-NOTERI-DEV"
BINARY_SHA256 = "14e0fff0449ce3c3a7fe9db8b8b32089274db5f835d4c99f5af7c32dcbf08981"
MODEL_NAME = "qwen2.5-coder:7b"
MODEL_DIGEST_PREFIX = "dae161e27b0e"
IDEMPOTENCY_KEY = "noteri:ollama:dev:start-qwen7b:20261115:v1"
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")


class StartBlocked(RuntimeError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise StartBlocked(reason)


def fixed_binary(local: Path) -> Path:
    require(local.is_absolute(), "LOCALAPPDATA_INVALID")
    path = local / "Programs" / "Ollama" / "ollama.exe"
    require(path_safe(path, local) and path.is_file(), "BINARY_PATH_INVALID")
    require(0 < path.stat().st_size <= 512 * 1024 * 1024, "BINARY_SIZE_INVALID")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise StartBlocked("BINARY_READ_FAILED") from None
    require(digest.hexdigest() == BINARY_SHA256, "BINARY_SHA_MISMATCH")
    return path


def validate_request(*, action: str, environment: str, correlation_id: str,
                     idempotency_key: str, confirmation: str, expected_sha: str,
                     host: str, platform: str, profile: str) -> None:
    require(action == ACTION and environment == ENVIRONMENT, "TARGET_UNAUTHORIZED")
    require(host.casefold() == "noteri" and platform == "nt", "HOST_UNAUTHORIZED")
    require(profile == "NORMAL", "PROFILE_NOT_NORMAL")
    require(bool(CORRELATION.fullmatch(correlation_id)), "CORRELATION_INVALID")
    require(idempotency_key == IDEMPOTENCY_KEY, "IDEMPOTENCY_INVALID")
    require(confirmation == CONFIRM, "OWNER_CONFIRMATION_INVALID")
    require(bool(SHA40.fullmatch(expected_sha)), "SOURCE_SHA_INVALID")


def eligible_preflight(*, expected_sha: str, correlation_id: str, root: Path
                       ) -> dict[str, Any]:
    report = preflight_plan(
        expected_sha=expected_sha, correlation_id=correlation_id,
        confirm=PREFLIGHT_CONFIRM, host=socket.gethostname(),
        platform=os.name, root=root, profile=watchdog.runtime_profile(),
    )
    require(report["status"] == "PREFLIGHT_CANDIDATE"
            and report["windows_tcp_listener"] == "ABSENT"
            and report["process"] == "ABSENT"
            and report["port"] in {"CLOSED", "UNKNOWN"},
            "OLLAMA_EXISTING_OR_INCONCLUSIVE")
    binaries = report["binaries"]
    require(len(binaries) == 3
            and sum(item["status"] == "PRESENT" for item in binaries) == 1
            and binaries[0]["candidate"] == "USER_PROGRAM"
            and binaries[0]["status"] == "PRESENT"
            and binaries[0]["sha256"] == BINARY_SHA256,
            "OLLAMA_BINARY_UNTRUSTED")
    return report


def model_readback() -> str | None:
    model = read_model_tags()
    digest = model.get("digest")
    return (digest if model.get("status") == "PRESENT"
            and model.get("present") is True
            and isinstance(digest, str)
            and len(digest) == 64
            and digest.startswith(MODEL_DIGEST_PREFIX)
            else None)


def receipt_root(local: Path) -> Path:
    base = local / "ReqSys"
    target = base / "OllamaRecovery"
    for segment in (local, base, target):
        require(not segment.is_symlink()
                and not (hasattr(os.path, "isjunction")
                         and os.path.isjunction(str(segment))),
                "RECEIPT_ROOT_UNSAFE")
    target.mkdir(parents=True, exist_ok=True)
    return target


def safe_existing_receipt(path: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    require(not path.is_symlink() and path.is_file()
            and path.stat().st_size <= 8192, "RECEIPT_UNSAFE")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise StartBlocked("RECEIPT_INVALID") from None
    require(type(receipt) is dict
            and receipt.get("schema_version") == SCHEMA
            and receipt.get("idempotency_key") == IDEMPOTENCY_KEY
            and receipt.get("binary_sha256") == BINARY_SHA256
            and type(receipt.get("pid")) is int
            and receipt["pid"] > 0, "RECEIPT_INVALID")
    return receipt


def save_receipt(path: Path, payload: dict[str, Any]) -> None:
    # Exclusive create: never overwrite an existing receipt or third-party data.
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        raise StartBlocked("RECEIPT_CREATE_FAILED") from None
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(json.dumps(payload, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())
    require(safe_existing_receipt(path) == payload, "RECEIPT_READBACK_FAILED")


def spawn_exact_binary(binary: Path) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["OLLAMA_HOST"] = "127.0.0.1:11434"
    env["OLLAMA_NO_CLOUD"] = "1"
    env["OLLAMA_ORIGINS"] = ""
    try:
        return subprocess.Popen(
            [str(binary), "serve"],
            cwd=str(binary.parent),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False, env=env,
            close_fds=True, creationflags=(subprocess.DETACHED_PROCESS
                                          | subprocess.CREATE_NO_WINDOW),
        )
    except OSError:
        raise StartBlocked("OLLAMA_SPAWN_FAILED") from None


def rollback_owned(process: subprocess.Popen[bytes]) -> bool:
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
    except (OSError, subprocess.SubprocessError):
        return False
    return (process.poll() is not None
            and inspect_windows_listener() == "ABSENT")


def start_once(*, expected_sha: str, correlation_id: str,
               local: Path, root: Path) -> dict[str, Any]:
    binary = fixed_binary(local)
    # The process is never started if a typed preflight does not attest absence.
    eligible_preflight(expected_sha=expected_sha, correlation_id=correlation_id,
                       root=root)
    state = receipt_root(local)
    lock = state / "start.lock"
    receipt_path = state / "start-v1.json"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        raise StartBlocked("START_LOCK_BUSY") from None
    process: subprocess.Popen[bytes] | None = None
    try:
        os.close(fd)
        require(safe_existing_receipt(receipt_path) is None,
                "EXISTING_RECEIPT_REQUIRES_READBACK")
        # Race check performed while holding the dedicated start lock.
        require(inspect_windows_listener() == "ABSENT"
                and ollama_process_state() == "ABSENT",
                "START_RACE_OR_EXISTING_PROCESS")
        process = spawn_exact_binary(binary)
        for _ in range(16):
            if process.poll() is not None:
                break
            if inspect_windows_listener() == "LISTENING":
                digest = model_readback()
                if digest is not None:
                    receipt = {
                        "schema_version": SCHEMA,
                        "idempotency_key": IDEMPOTENCY_KEY,
                        "source_sha": expected_sha,
                        "binary_sha256": BINARY_SHA256,
                        "pid": process.pid,
                        "model_digest": digest,
                        "cloud_opt_out_requested": True,
                    }
                    save_receipt(receipt_path, receipt)
                    return {
                        "result": "OLLAMA_STARTED_MODEL_ATTESTED",
                        "source_sha": expected_sha, "correlation_id": correlation_id,
                        "pid": process.pid, "model_digest": digest,
                        "listener": "LISTENING", "api": "MODEL_ATTESTED",
                        "state_changed": True, "receipt_reloaded": True,
                        "cloud_opt_out_requested": True,
                        "independent_validator_required": True,
                    }
            time.sleep(0.75)
        rolled_back = rollback_owned(process)
        return {
            "result": "BLOCKED_OLLAMA_READBACK_AND_ROLLBACK",
            "source_sha": expected_sha,
            "correlation_id": correlation_id,
            "model_attested": False, "state_changed": not rolled_back,
            "rollback_verified": rolled_back, "pid": process.pid,
        }
    except (OSError, StartBlocked) as exc:
        restored = rollback_owned(process) if process is not None else True
        return {
            "result": "BLOCKED_OLLAMA_START_AND_ROLLBACK",
            "reason": str(exc) if type(exc) is StartBlocked else "STATE_IO_FAILED",
            "source_sha": expected_sha, "state_changed": not restored,
            "rollback_verified": restored,
        }
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-version", type=int, required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        require(args.schema_version == SCHEMA, "SCHEMA_INVALID")
        validate_request(
            action=args.action, environment=args.environment,
            correlation_id=args.correlation_id,
            idempotency_key=args.idempotency_key,
            confirmation=args.confirm, expected_sha=args.expected_sha,
            host=socket.gethostname(), platform=os.name,
            profile=watchdog.runtime_profile(),
        )
        result = start_once(
            expected_sha=args.expected_sha, correlation_id=args.correlation_id,
            root=Path(__file__).resolve().parents[1],
            local=Path(os.environ.get("LOCALAPPDATA", "")),
        )
    except (StartBlocked, OSError, ValueError) as exc:
        result = {
            "result": "OLLAMA_START_BLOCKED",
            "reason": str(exc) if type(exc) is StartBlocked else "PRECONDITION_UNAVAILABLE",
            "state_changed": False,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "OLLAMA_STARTED_MODEL_ATTESTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
