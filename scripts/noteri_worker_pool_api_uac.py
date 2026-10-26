#!/usr/bin/env python3
"""Request UAC for one qualified native Worker Pool API activation."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scripts import noteri_worker_pool_native_activation as activation
from scripts import noteri_worker_pool_credential_reference as reference

CONFIRM = "LAUNCH-NOTERI-WORKER-POOL-API-UAC"
SW_SHOWNORMAL = 1
CHILD_RESULTS = {"API_ACTIVATED", "ALREADY_ACTIVE", "BLOCKED_EXISTING",
                 "BLOCKED_ELEVATION_REQUIRED", "BLOCKED_PRECONDITION",
                 "BLOCKED_ACTIVATION_ROLLED_BACK", "BLOCKED_REGISTRATION_AMBIGUOUS",
                 "BLOCKED_ROLLBACK", "BLOCKED_CHILD_EXCEPTION"}
PHASES = {None, "materialize", "register", "task_readback", "start", "api_readback"}


def elevated_arguments(receipt: Path) -> str:
    return subprocess.list2cmdline([
        "-B", "-m", "scripts.noteri_worker_pool_api_elevated_entry",
        "--receipt", str(receipt), "--confirm", activation.CONFIRM,
    ])


def launch(*, confirm: str, timeout_seconds: int = 45) -> dict:
    if confirm != CONFIRM:
        return {"result": "BLOCKED_ACTION", "activated": False}
    source = Path(activation.__file__).resolve().parent
    repo = source.parent
    local = Path(os.environ["LOCALAPPDATA"])
    root, _, _ = activation.qualify(local, source)
    if activation.is_admin():
        return activation.activate(local, source)
    receipt = root / f"activation-uac-{uuid.uuid4().hex}.json"
    result = int(ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, elevated_arguments(receipt), str(repo), SW_SHOWNORMAL))
    if result <= 32:
        return {"result": "BLOCKED_UAC_LAUNCH", "activated": False}
    deadline = time.monotonic() + max(5, min(timeout_seconds, 120))
    child = None
    while time.monotonic() < deadline:
        try:
            if receipt.is_file():
                child = json.loads(receipt.read_text(encoding="utf-8"))
                if (child.get("source_sha") != reference.SOURCE_SHA
                        or child.get("schema_version") != "1"
                        or child.get("result") not in CHILD_RESULTS
                        or child.get("phase") not in PHASES
                        or not isinstance(child.get("elevation_observed"), bool)):
                    return {"result": "BLOCKED_UAC_RECEIPT", "activated": False}
                if child.get("result") != "API_ACTIVATED":
                    return {"result": "BLOCKED_UAC_CHILD", "activated": False,
                            "child_result": child.get("result", "BLOCKED_UNKNOWN"),
                            "phase": child.get("phase"),
                            "elevation_observed": child.get("elevation_observed")}
            existing = activation.existing_task(local, source)
            if existing is not None and activation.verify_api(*existing[1:]):
                return {"result": "API_ACTIVE", "activated": True, "state_changed": True,
                        "task_s4u_verified": True, "contract_v1_verified": True,
                        "negative_auth_verified": True}
        except (OSError, ValueError, TimeoutError):
            pass
        time.sleep(1)
    return {"result": ("BLOCKED_UAC_READBACK" if child else "BLOCKED_UAC_PENDING"),
            "activated": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", default="")
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    base = {"schema_version": "1", "source_sha": reference.SOURCE_SHA,
            "state_changed": False}
    try:
        payload = {**base, **launch(confirm=args.confirm,
                                   timeout_seconds=args.timeout_seconds)}
    except Exception:
        payload = {**base, "result": "BLOCKED_PRECONDITION", "activated": False}
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["result"] in {"API_ACTIVE", "API_ACTIVATED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
