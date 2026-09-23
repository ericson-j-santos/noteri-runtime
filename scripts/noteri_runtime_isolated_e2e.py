#!/usr/bin/env python3
"""Executa E2E físico isolado do runtime Noteri no próprio host."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_inputs(*, host: str, expected_sha: str, correlation_id: str) -> None:
    if host.casefold() != "noteri":
        raise RuntimeError(f"host_not_authorized:{host}")
    if not _SHA_RE.fullmatch(expected_sha.strip()):
        raise ValueError("expected_sha_invalid")
    if not 8 <= len(correlation_id.strip()) <= 128:
        raise ValueError("correlation_id_invalid")


def choose_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"json_object_expected:{path.name}")
    return payload


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def health(port: int, timeout: float = 1.0) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def wait_for_agent(port: int, process: subprocess.Popen[str], timeout: float = 8.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = health(port)
        if observed is not None:
            if (
                observed.get("ok") is True
                and observed.get("service") == "noteri-host-profile-agent"
                and str(observed.get("host") or "").casefold() == "noteri"
                and observed.get("loopback_only") is True
            ):
                return observed
            raise RuntimeError("unexpected_health_payload")
        if process.poll() is not None:
            raise RuntimeError(f"agent_exited_early:{process.returncode}")
        time.sleep(0.2)
    raise RuntimeError("agent_health_timeout")


def parse_e2e_stdout(stdout: str) -> dict[str, Any]:
    rows = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not rows:
        raise RuntimeError("e2e_stdout_empty")
    payload = json.loads(rows[-1])
    if not isinstance(payload, dict):
        raise RuntimeError("e2e_payload_invalid")
    return payload


def validate_independent_state(
    *,
    profile_path: Path,
    audit_path: Path,
    correlation_id: str,
    e2e: dict[str, Any],
) -> dict[str, Any]:
    profile = read_json(profile_path)
    if profile.get("profile") != "NORMAL" or profile.get("accepts_new_development") is not True:
        raise RuntimeError("final_profile_not_normal")

    rows = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    own_rows = [
        row
        for row in rows
        if isinstance(row, dict) and str(row.get("correlation_id") or "").startswith(correlation_id + "-")
    ]
    if not own_rows:
        raise RuntimeError("audit_correlation_missing")
    if not any(row.get("after_profile") == "ESTUDO" and row.get("changed") is True for row in own_rows):
        raise RuntimeError("audit_estudo_transition_missing")
    if not any(row.get("after_profile") == "NORMAL" and row.get("changed") is True for row in own_rows):
        raise RuntimeError("audit_normal_transition_missing")
    if not any(row.get("after_profile") == "NORMAL" and row.get("changed") is False for row in own_rows):
        raise RuntimeError("audit_idempotent_replay_missing")

    negative = e2e.get("negative_control")
    if not isinstance(negative, dict) or negative.get("http_status") != 409:
        raise RuntimeError("negative_control_missing")
    if negative.get("error") != "host_target_mismatch":
        raise RuntimeError("negative_control_wrong_error")

    return {
        "profile": profile.get("profile"),
        "accepts_new_development": profile.get("accepts_new_development"),
        "audit_rows_for_correlation": len(own_rows),
        "estudo_transition": True,
        "normal_transition": True,
        "idempotent_replay": True,
        "negative_control": True,
    }


def terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    agent_script = root / "scripts" / "noteri_host_profile_agent.py"
    e2e_script = root / "scripts" / "noteri_host_profile_agent_e2e.py"
    validate_inputs(
        host=socket.gethostname(),
        expected_sha=args.expected_sha,
        correlation_id=args.correlation_id,
    )
    if not agent_script.is_file() or not e2e_script.is_file():
        raise RuntimeError("runtime_scripts_missing")

    evidence: dict[str, Any] = {
        "schema_version": "1",
        "ok": False,
        "host": socket.gethostname(),
        "expected_sha": args.expected_sha.lower(),
        "correlation_id": args.correlation_id,
        "started_at": now_iso(),
        "production_touched": False,
        "secrets_read": False,
        "rdc_required": False,
    }

    with tempfile.TemporaryDirectory(prefix="noteri-runtime-e2e-") as temp_dir:
        temp = Path(temp_dir)
        profile_path = temp / "host-profile.json"
        audit_path = temp / "host-profile-audit.jsonl"
        port = choose_loopback_port()
        evidence["port"] = port
        command = [
            sys.executable,
            str(agent_script),
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
            "--host",
            "Noteri",
            "--profile-path",
            str(profile_path),
            "--audit-path",
            str(audit_path),
        ]
        process = subprocess.Popen(
            command,
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            evidence["health"] = wait_for_agent(port, process)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(e2e_script),
                    "--port",
                    str(port),
                    "--correlation-prefix",
                    args.correlation_id,
                ],
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            evidence["e2e_exit_code"] = completed.returncode
            e2e = parse_e2e_stdout(completed.stdout)
            evidence["e2e"] = e2e
            if completed.returncode != 0 or e2e.get("ok") is not True:
                raise RuntimeError("physical_e2e_failed")
            evidence["independent_readback"] = validate_independent_state(
                profile_path=profile_path,
                audit_path=audit_path,
                correlation_id=args.correlation_id,
                e2e=e2e,
            )
            evidence["ok"] = True
            evidence["result"] = "NOTERI_RUNTIME_ISOLATED_E2E_OK"
            return evidence
        finally:
            terminate(process)
            evidence["finished_at"] = now_iso()


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E físico isolado do noteri-runtime")
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--evidence-path", type=Path, required=True)
    args = parser.parse_args()

    payload: dict[str, Any]
    try:
        payload = run(args)
        code = 0
    except Exception as exc:
        payload = {
            "schema_version": "1",
            "ok": False,
            "host": socket.gethostname(),
            "expected_sha": args.expected_sha.lower(),
            "correlation_id": args.correlation_id,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "production_touched": False,
            "secrets_read": False,
            "rdc_required": False,
            "finished_at": now_iso(),
        }
        code = 1

    atomic_json(args.evidence_path, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
