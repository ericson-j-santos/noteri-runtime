#!/usr/bin/env python3
"""Plano somente leitura para recuperar Ollama DEV no host Noteri.

Esta capability NÃO inicializa programas, serviços ou modelos. É executável
somente após Session Launcher e Command Gateway Risk1 governados.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any

from noteri_watchdog_readonly_inventory import (
    ollama_port_state, ollama_process_state, read_model_tags,
)
import noteri_control_plane_watchdog as watchdog

CONFIRM = "PLAN-NOTERI-OLLAMA-RECOVERY-READONLY"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
LIMIT = 512 * 1024 * 1024


class PlanBlocked(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PlanBlocked(code)


def source_sha(root: Path) -> str:
    try:
        observed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=8, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlanBlocked("SOURCE_SHA_UNAVAILABLE") from exc
    value = observed.stdout.strip().lower()
    require(observed.returncode == 0 and SHA40.fullmatch(value) is not None,
            "SOURCE_SHA_UNAVAILABLE")
    return value


def path_safe(path: Path, root: Path) -> bool:
    """Reject symlinks/junctions in the fixed path and its known root."""
    try:
        base = root.absolute()
        target = path.absolute()
        if not target.is_relative_to(base):
            return False
        current = target
        while True:
            if current.is_symlink() or (
                hasattr(os.path, "isjunction") and os.path.isjunction(str(current))
            ):
                return False
            if current == base:
                break
            current = current.parent
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def candidate(label: str, root: Path | None, relative: str) -> dict[str, Any]:
    outcome: dict[str, Any] = {
        "candidate": label, "status": "NOT_CONFIGURED",
        "sha256": None, "bytes": None,
    }
    if root is None:
        return outcome
    path = root / relative
    if not path_safe(path, root):
        outcome["status"] = "UNSAFE"
        return outcome
    try:
        if not path.exists():
            outcome["status"] = "MISSING"
            return outcome
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= LIMIT:
            outcome["status"] = "INVALID"
            return outcome
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        check = path.stat()
        if (check.st_size, check.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
            outcome["status"] = "CHANGED"
            return outcome
        outcome.update(status="PRESENT", sha256=digest.hexdigest(), bytes=info.st_size)
    except OSError:
        outcome["status"] = "UNAVAILABLE"
    return outcome


def root_env(key: str) -> Path | None:
    value = os.environ.get(key)
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else None


def plan(*, expected_sha: str, correlation_id: str, confirm: str,
         host: str, platform: str, root: Path,
         profile: str) -> dict[str, Any]:
    require(confirm == CONFIRM, "CONFIRMATION_INVALID")
    require(SHA40.fullmatch(expected_sha) is not None, "EXPECTED_SHA_INVALID")
    require(CORRELATION.fullmatch(correlation_id) is not None, "CORRELATION_INVALID")
    require(host.casefold() == "noteri" and platform == "nt",
            "HOST_NOT_AUTHORIZED")
    require(source_sha(root) == expected_sha, "SOURCE_SHA_MISMATCH")
    require(profile == "NORMAL", "PROFILE_NOT_NORMAL")

    local = root_env("LOCALAPPDATA")
    programs = root_env("ProgramFiles")
    binaries = [
        candidate("USER_PROGRAM", local, "Programs/Ollama/ollama.exe"),
        candidate("USER_LOCAL", local, "Ollama/ollama.exe"),
        candidate("MACHINE_PROGRAM", programs, "Ollama/ollama.exe"),
    ]
    detail: dict[str, Any] = {}
    process = ollama_process_state()
    port = ollama_port_state(detail=detail)
    api = read_model_tags() if port == "OPEN" else {
        "status": "NOT_QUERIED", "present": False, "digest": None,
    }

    existing = [item for item in binaries if item["status"] == "PRESENT"]
    # An unknown port is NOT evidence of absence. Never start automatically.
    status = ("PREFLIGHT_CANDIDATE" if
              process == "ABSENT" and port == "CLOSED" and len(existing) == 1
              else "BLOCKED_OR_INCONCLUSIVE")
    return {
        "result": "NOTERI_OLLAMA_RECOVERY_PLAN_READONLY",
        "correlation_id": correlation_id,
        "source_sha": expected_sha,
        "host_validated": True,
        "profile": profile,
        "binaries": binaries,
        "process": process,
        "port": port,
        "socket_error_code": detail.get("socket_error_code"),
        "api": api,
        "status": status,
        "recovery_authorized": False,
        "restart_performed": False,
        "model_installed": False,
        "state_changed": False,
        "next_action": "OWNER_APPROVAL_AND_RISK2_CAPABILITY_REQUIRED",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        result = plan(expected_sha=args.expected_sha, correlation_id=args.correlation_id,
                      confirm=args.confirm, host=socket.gethostname(),
                      platform=os.name, root=Path(__file__).resolve().parents[1],
                      profile=watchdog.runtime_profile())
    except (PlanBlocked, OSError, ValueError) as exc:
        result = {
            "result": "NOTERI_OLLAMA_RECOVERY_PLAN_BLOCKED",
            "reason": str(exc) if isinstance(exc, PlanBlocked) else "DEPENDENCY_UNAVAILABLE",
            "recovery_authorized": False, "state_changed": False,
        }
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
