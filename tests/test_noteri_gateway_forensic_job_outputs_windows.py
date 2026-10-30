"""PowerShell 5.1 producer contract on hosted Windows, never on the Noteri host."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-gateway-forensic-readonly.yml"
START = "          $json = [string]($report | ConvertTo-Json -Depth 8 -Compress)"
END = "          Write-Output 'NOTERI_GATEWAY_FORENSIC_READONLY_OK'"


def _producer_body():
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert raw.count(START) == 1 and raw.count(END) == 1
    start = raw.index(START)
    end = raw.index(END, start) + len(END)
    return raw[start:end]


def _run_powershell_producer(tmp_path, text: str):
    outfile = tmp_path / "github-outputs.txt"
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$report = [pscustomobject]@{ result = 'NOTERI_GATEWAY_FORENSIC_READONLY';"
        " metadata_checked_files = 7; host_ready = $false; recovery_authorized = $false;"
        " test_value = $env:TEST_VALUE }\n"
        + _producer_body()
    )
    env = dict(os.environ, TEST_VALUE=text, GITHUB_OUTPUT=str(outfile))
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=30, check=False,
    )
    return result, outfile


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_actual_windows_powershell_producer_emits_matching_sha256(tmp_path):
    completed, path = _run_powershell_producer(tmp_path, "sanitized")
    assert completed.returncode == 0, completed.stderr
    assert "NOTERI_GATEWAY_FORENSIC_READONLY_OK" in completed.stdout
    pairs = dict(line.split("=", 1) for line in path.read_text(encoding="ascii").splitlines())
    assert set(pairs) == {"receipt_b64", "receipt_sha256"}
    raw = base64.b64decode(pairs["receipt_b64"], validate=True)
    assert hashlib.sha256(raw).hexdigest() == pairs["receipt_sha256"]
    obj = json.loads(raw)
    assert obj["result"] == "NOTERI_GATEWAY_FORENSIC_READONLY"
    assert obj["test_value"] == "sanitized"
    assert obj["host_ready"] is False and obj["recovery_authorized"] is False


@pytest.mark.skipif(os.name != "nt", reason="requires hosted Windows PowerShell 5.1")
def test_windows_producer_rejects_oversized_receipt_before_output(tmp_path):
    completed, path = _run_powershell_producer(tmp_path, "x" * 9000)
    assert completed.returncode != 0
    assert "NOTERI_GATEWAY_FORENSIC_OUTPUT_SIZE_INVALID" in (completed.stderr + completed.stdout)
    assert not path.exists() or not path.read_text(encoding="ascii").strip()
