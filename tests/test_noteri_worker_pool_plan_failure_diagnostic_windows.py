"""Exercises the actual bounded diagnostic block in hosted Windows PowerShell 5.1.

All input is synthetic. Never accesses Noteri, tokens, Session Launcher or Gateway.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-worker-pool-native-plan.yml"
START = "          # BEGIN bounded plan-failure classification (no raw Gateway evidence)."
END = "          # END bounded plan-failure classification."


def _block() -> str:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert raw.count(START) == raw.count(END) == 1
    return raw[raw.index(START):raw.index(END) + len(END)]


def _invoke(payload: dict, code: int = 0) -> subprocess.CompletedProcess[str]:
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$evidence = $env:SYNTHETIC_RECEIPT | ConvertFrom-Json\n"
        f"$exitCode = {code}\n"
        + _block()
        + "\nWrite-Output 'SAFE_DIAG_CONTINUED'\n"
    )
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "SYNTHETIC_RECEIPT": json.dumps(payload)},
        capture_output=True, text=True, timeout=30, check=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
@pytest.mark.parametrize("source_result", ["STAGE_PLAN_READY", "ALREADY_STAGED"])
def test_valid_plan_does_not_emit_failure(source_result: str) -> None:
    done = _invoke({"result": source_result, "source_sha": "a" * 40})
    assert done.returncode == 0, done.stderr
    assert "SAFE_DIAG_CONTINUED" in done.stdout


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
@pytest.mark.parametrize(
    "receipt,exit_code,expected", [
        ({"result": "ALREADY_STAGED"}, 2, "ALREADY_STAGED"),
        ({"result": "STAGE_BLOCKED", "reason": "profile_unavailable"}, 2, "profile_unavailable"),
        ({"result": "STAGE_BLOCKED", "reason": "profile_not_normal"}, 2, "profile_not_normal"),
        ({"result": "STAGE_BLOCKED", "reason": "source_identity_unverified"}, 2, "source_identity_unverified"),
        ({"result": "STAGE_PLAN_READY"}, 1, "GATEWAY_NONZERO"),
        ({"result": "UNKNOWN", "private": "DO_NOT_PRINT"}, 2, "GATEWAY_NONZERO"),
        ({"result": "STAGE_BLOCKED", "reason": "DO_NOT_PRINT_C:/sensitive"}, 2, "STAGE_BLOCKED_UNKNOWN"),
    ],
)
def test_failed_plan_reports_only_fixed_allowlisted_code(
    receipt: dict, exit_code: int, expected: str
) -> None:
    done = _invoke(receipt, exit_code)
    assert done.returncode != 0
    output = done.stdout + done.stderr
    assert "STAGE_PLAN_BLOCKED_" + expected in output
    assert "SAFE_DIAG_CONTINUED" not in output
    assert "DO_NOT_PRINT" not in output
    assert "C:/sensitive" not in output


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_same_failure_is_idempotently_classified() -> None:
    receipt = {"result": "STAGE_BLOCKED", "reason": "profile_unavailable"}
    for _ in range(2):
        done = _invoke(receipt, 2)
        assert done.returncode != 0
        assert "STAGE_PLAN_BLOCKED_profile_unavailable" in done.stdout + done.stderr
