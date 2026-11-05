"""Execute the actual Worker Pool plan receipt block on hosted Windows PowerShell 5.1.

Only synthetic input is used. No Noteri host, Gateway, credentials, or activation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-worker-pool-native-plan.yml"
SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
START = "          # Validate and project only six public fields before leaving the Noteri host."
END = "          Write-Output 'NOTERI_STAGE_PLAN_RECEIPT_OK'"
FIELDS = {"result", "source_sha", "file_count", "state_changed", "activated", "secrets_read"}
VALID = {
    "result": "STAGE_PLAN_READY",
    "source_sha": SOURCE_SHA,
    "file_count": 3,
    "state_changed": False,
    "activated": False,
    "secrets_read": False,
}


def _actual_producer_block() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert workflow.count(START) == workflow.count(END) == 1
    start = workflow.index(START)
    end = workflow.index(END, start) + len(END)
    return workflow[start:end]


def _execute(tmp_path: Path, payload: dict):
    outfile = tmp_path / "github-output.txt"
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$evidence = $env:SYNTHETIC_PLAN_RECEIPT | ConvertFrom-Json\n"
        + _actual_producer_block()
    )
    env = dict(
        os.environ,
        SYNTHETIC_PLAN_RECEIPT=json.dumps(payload, separators=(",", ":")),
        WORKER_POOL_SHA=SOURCE_SHA,
        GITHUB_OUTPUT=str(outfile),
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return completed, outfile


def _decoded_output(path: Path) -> tuple[dict, bytes, str]:
    items = dict(line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines())
    assert set(items) == {"receipt_b64", "receipt_sha256"}
    raw = base64.b64decode(items["receipt_b64"], validate=True)
    assert len(raw) <= 4096
    assert hashlib.sha256(raw).hexdigest() == items["receipt_sha256"]
    return json.loads(raw), raw, items["receipt_sha256"]


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_actual_worker_pool_projection_sends_only_allowlisted_fields(tmp_path: Path) -> None:
    result, outfile = _execute(tmp_path, VALID)
    assert result.returncode == 0, result.stderr
    assert "NOTERI_STAGE_PLAN_RECEIPT_OK" in result.stdout
    receipt, _raw, _digest = _decoded_output(outfile)
    assert set(receipt) == FIELDS
    assert receipt == VALID


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
@pytest.mark.parametrize(
    "change,reason",
    [
        ({"unexpected_token": "FAKE_VALUE_NEVER_USE"}, "STAGE_PLAN_EVIDENCE_SCHEMA_INVALID"),
        ({"file_count": 0}, "STAGE_PLAN_FILE_COUNT_INVALID"),
        ({"file_count": 801}, "STAGE_PLAN_FILE_COUNT_INVALID"),
        ({"file_count": "3"}, "STAGE_PLAN_FILE_COUNT_INVALID"),
        ({"file_count": 2.5}, "STAGE_PLAN_FILE_COUNT_INVALID"),
        ({"file_count": None}, "STAGE_PLAN_FILE_COUNT_INVALID"),
    ],
)
def test_actual_projection_blocks_invalid_data_before_export(
    tmp_path: Path, change: dict, reason: str
) -> None:
    data = {**VALID, **change}
    result, outfile = _execute(tmp_path, data)
    assert result.returncode != 0
    assert reason in result.stderr + result.stdout
    assert not outfile.exists() or not outfile.read_text(encoding="ascii").strip()


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_actual_projection_rejects_missing_field(tmp_path: Path) -> None:
    data = dict(VALID)
    del data["activated"]
    result, outfile = _execute(tmp_path, data)
    assert result.returncode != 0
    assert "STAGE_PLAN_EVIDENCE_SCHEMA_INVALID" in result.stderr + result.stdout
    assert not outfile.exists() or not outfile.read_text(encoding="ascii").strip()


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_repeat_same_input_produces_same_digest_without_host_state(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    a, apath = _execute(first, VALID)
    b, bpath = _execute(second, VALID)
    assert a.returncode == b.returncode == 0, (a.stderr, b.stderr)
    _data_a, bytes_a, digest_a = _decoded_output(apath)
    _data_b, bytes_b, digest_b = _decoded_output(bpath)
    assert bytes_a == bytes_b and digest_a == digest_b
