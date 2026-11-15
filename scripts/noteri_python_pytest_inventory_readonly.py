#!/usr/bin/env python3
"""Read-only inventory of already present, pinned Python pytest environments.

Never installs packages, accesses private tokens, starts a service, runs tests,
uses network or scans arbitrary drives. Probe only the current interpreter,
the hash-pinned uv Python, and the manifest-pinned Worker Pool virtualenv.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import noteri_control_plane_watchdog as watchdog
import noteri_worker_pool_native_stage as stage
import noteri_worker_pool_native_venv as venv
from noteri_ollama_recovery_preflight import source_sha
from noteri_worker_pool_credential_reference import SOURCE_SHA

CONFIRM = "INVENTORY-NOTERI-PYTEST-READONLY"
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
PROBE_CODE = (
    "import importlib.metadata as im,json,sys\n"
    "try:\n pytest=im.version('pytest')\n"
    "except im.PackageNotFoundError:\n pytest=None\n"
    "print(json.dumps({'python':'.'.join(map(str,sys.version_info[:2])),"
    "'pytest':pytest},sort_keys=True))"
)


class Blocked(ValueError):
    pass


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_candidates(localappdata: Path, appdata: Path) -> dict[str, Path]:
    candidates = {"gateway_python": Path(sys.executable)}
    uv = appdata / venv.BASE_PYTHON_RELATIVE
    stage.ensure_no_link_components(uv)
    if uv.is_file() and _file_sha(uv) == venv.BASE_PYTHON_SHA256:
        candidates["pinned_uv_python311"] = uv
    staged = (localappdata / "ReqSys" / "NoteriWorkerPool" / "venvs"
              / SOURCE_SHA)
    target = staged / "Scripts" / "python.exe"
    receipt = staged / "noteri-venv-manifest.json"
    stage.ensure_no_link_components(target)
    stage.ensure_no_link_components(receipt)
    if target.is_file() and receipt.is_file() and receipt.stat().st_size < 8192:
        try:
            manifest = json.loads(receipt.read_text(encoding="utf-8"))
            if (type(manifest) is dict
                    and manifest.get("source_sha") == SOURCE_SHA
                    and manifest.get("python_sha256") == _file_sha(target)):
                candidates["worker_pool_pinned_venv"] = target
        except (OSError, ValueError, TypeError):
            pass
    return candidates


def _probe(label: str, python: Path) -> dict:
    if not python.is_file() or python.is_symlink():
        return {"label": label, "result": "UNAVAILABLE"}
    try:
        process = subprocess.run(
            [str(python), "-B", "-I", "-c", PROBE_CODE],
            stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=12, check=False, env={
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
                "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
                "TEMP": os.environ.get("TEMP", ""),
                "TMP": os.environ.get("TMP", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        if process.returncode != 0 or not 2 <= len(process.stdout) <= 320:
            return {"label": label, "result": "INTERPRETER_UNVERIFIED"}
        doc = json.loads(process.stdout)
        if (type(doc) is not dict
                or set(doc) != {"python", "pytest"}
                or not isinstance(doc["python"], str)
                or not re.fullmatch(r"3\.[0-9]{1,2}", doc["python"])
                or (doc["pytest"] is not None
                    and (not isinstance(doc["pytest"], str)
                         or not re.fullmatch(r"[0-9A-Za-z._+-]{1,40}",
                                             doc["pytest"])))):
            return {"label": label, "result": "INTERPRETER_SCHEMA_INVALID"}
        return {"label": label,
                "result": "PYTEST_PRESENT" if doc["pytest"] else "PYTEST_MISSING",
                "python_version": doc["python"],
                "pytest_version": doc["pytest"]}
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return {"label": label, "result": "INTERPRETER_UNVERIFIED"}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--confirm", required=True)
    args = p.parse_args()
    try:
        if (not SHA40.fullmatch(args.expected_head)
                or not CORRELATION.fullmatch(args.correlation_id)
                or args.confirm != CONFIRM
                or os.name != "nt" or socket.gethostname().casefold() != "noteri"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != args.expected_head):
            raise Blocked("HOST_PROFILE_SOURCE_NOT_ATTESTED")
        local = os.environ.get("LOCALAPPDATA")
        roaming = os.environ.get("APPDATA")
        if not local or not roaming:
            raise Blocked("HOST_APPDATA_NOT_AVAILABLE")
        available = _validated_candidates(Path(local), Path(roaming))
        probes = [_probe(label, python) for label, python in available.items()]
        print(json.dumps({
            "result": "PYTEST_EXISTING_RUNTIME_INVENTORY",
            "candidates_checked": len(probes),
            "pytest_available": any(p["result"] == "PYTEST_PRESENT" for p in probes),
            "candidates": probes,
            "install_performed": False, "network_accessed": False,
            "state_changed": False, "credentials_read": False,
            "correlation_id": args.correlation_id,
            "source_sha": args.expected_head,
        }, sort_keys=True))
        return 0
    except (Blocked, OSError, stage.StageBlocked) as exc:
        print(json.dumps({"result": "PYTEST_RUNTIME_INVENTORY_BLOCKED",
                          "reason": str(exc) if isinstance(exc, Blocked)
                          else "INTEGRITY_UNAVAILABLE",
                          "state_changed": False},sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
