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
from pathlib import Path

from scripts import noteri_worker_pool_native_activation as activation
from scripts import noteri_worker_pool_credential_reference as reference

CONFIRM = "LAUNCH-NOTERI-WORKER-POOL-API-UAC"
SW_SHOWNORMAL = 1


def elevated_arguments() -> str:
    return subprocess.list2cmdline([
        "-B", "-m", "scripts.noteri_worker_pool_native_activation",
        "--mode", "activate", "--confirm", activation.CONFIRM,
    ])


def launch(*, confirm: str, timeout_seconds: int = 45) -> dict:
    if confirm != CONFIRM:
        return {"result": "BLOCKED_ACTION", "activated": False}
    source = Path(activation.__file__).resolve().parent
    repo = source.parent
    local = Path(os.environ["LOCALAPPDATA"])
    activation.qualify(local, source)
    if activation.is_admin():
        return activation.activate(local, source)
    result = int(ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, elevated_arguments(), str(repo), SW_SHOWNORMAL))
    if result <= 32:
        return {"result": "BLOCKED_UAC_LAUNCH", "activated": False}
    deadline = time.monotonic() + max(5, min(timeout_seconds, 120))
    while time.monotonic() < deadline:
        try:
            existing = activation.existing_task(local, source)
            if existing is not None and activation.verify_api(*existing[1:]):
                return {"result": "API_ACTIVE", "activated": True, "state_changed": True,
                        "task_s4u_verified": True, "contract_v1_verified": True,
                        "negative_auth_verified": True}
        except (OSError, ValueError, TimeoutError):
            pass
        time.sleep(1)
    return {"result": "BLOCKED_UAC_PENDING", "activated": False}


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
