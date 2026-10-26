#!/usr/bin/env python3
"""Run one elevated activation and leave a private, sanitized outcome receipt."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path

from scripts import noteri_worker_pool_native_activation as activation
from scripts import noteri_worker_pool_api_uac as uac
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_venv as venv


def run(receipt: Path, confirm: str) -> dict:
    root, _, _ = venv._paths(Path(os.environ["LOCALAPPDATA"]))
    if (confirm != activation.CONFIRM or not receipt.is_absolute()
            or receipt.parent.resolve() != root.resolve()
            or not re.fullmatch(r"activation-uac-[0-9a-f]{32}\.json", receipt.name)
            or receipt.exists()):
        raise activation.Blocked("receipt_path")
    output = io.StringIO()
    original_argv = sys.argv
    try:
        sys.argv = ["activation", "--mode", "activate", "--confirm", activation.CONFIRM]
        with contextlib.redirect_stdout(output):
            activation.main()
        payload = json.loads(output.getvalue())
    except Exception:
        payload = {"result": "BLOCKED_CHILD_EXCEPTION", "activated": False}
    finally:
        sys.argv = original_argv
    if not isinstance(payload, dict) or payload.get("result") not in uac.CHILD_RESULTS:
        payload = {"result": "BLOCKED_CHILD_EXCEPTION", "activated": False}
    if payload.get("phase") not in uac.PHASES:
        payload["phase"] = None
    sanitized = {"schema_version": "1", "source_sha": reference.SOURCE_SHA,
                 "elevation_observed": activation.is_admin(),
                 "result": payload.get("result", "BLOCKED_CHILD_EXCEPTION"),
                 "activated": payload.get("activated") is True,
                 "phase": payload.get("phase"),
                 "diagnostic_id": (payload.get("diagnostic_id")
                                   if re.fullmatch(r"[0-9a-f]{32}",
                                                   str(payload.get("diagnostic_id")))
                                   else None)}
    temporary = receipt.with_suffix(".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(sanitized, stream, sort_keys=True)
    temporary.replace(receipt)
    return sanitized


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        result = run(args.receipt, args.confirm)
    except Exception:
        return 2
    return 0 if result["result"] == "API_ACTIVATED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
