from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts" / "noteri_sql_application_eventlog.py"
WORKFLOW = ROOT / ".github" / "workflows" / "noteri-sql-application-eventlog.yml"


def _parser_block() -> str:
    raw = WORKFLOW.read_text(encoding="utf-8")
    start_marker = "          $decoded = ConvertFrom-Json -InputObject $envelope.stdout"
    end_marker = "          if ($gatewayExit"
    start = raw.index(start_marker)
    end = raw.index(end_marker, start)
    return "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in raw[start:end].splitlines()
    )


def _run_parser(payload: Any) -> subprocess.CompletedProcess[str]:
    encoded = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) {{
  throw 'WINDOWS_POWERSHELL_5_1_REQUIRED'
}}
$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))
$envelope = [pscustomobject]@{{ stdout = $payload }}
{_parser_block()}
"""
    return subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )


def _record(event_id: Any) -> dict[str, Any]:
    return {"classification": "not_observed", "date": None, "id": event_id}


def test_probe_help_runs_with_workflow_python_isolation_flags() -> None:
    completed = subprocess.run(
        [
            "python3",
            "-E",
            "-s",
            "-B",
            str(PROBE),
            "--help",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--expected-sha" in completed.stdout


@pytest.mark.parametrize(
    "records",
    [
        [_record(0)],
        [_record(0), _record(26013)],
    ],
)
def test_windows_powershell_51_parses_one_or_two_root_array_records(
    records: list[dict[str, Any]],
) -> None:
    completed = _run_parser(records)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == records


def test_windows_powershell_51_accepts_int32_and_int64_ids() -> None:
    records = [_record(0), _record(26013), _record(4294967295)]
    completed = _run_parser(records)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == records


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ([], "OUTPUT_COUNT_INVALID"),
        ([_record(index) for index in range(17)], "OUTPUT_COUNT_INVALID"),
        (_record(0), "OUTPUT_ROOT_INVALID"),
    ],
)
def test_windows_powershell_51_rejects_invalid_root_or_count(
    payload: Any, error: str
) -> None:
    completed = _run_parser(payload)
    assert completed.returncode != 0
    assert error in completed.stderr


@pytest.mark.parametrize(
    "event_id",
    [
        "26013",
        True,
        1.5,
        None,
        -1,
        4294967296,
    ],
)
def test_windows_powershell_51_rejects_non_integer_or_out_of_range_id(
    event_id: Any,
) -> None:
    completed = _run_parser([_record(event_id)])
    assert completed.returncode != 0
    assert "OUTPUT_ID_INVALID" in completed.stderr
