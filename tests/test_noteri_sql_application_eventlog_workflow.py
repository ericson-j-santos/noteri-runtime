from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "noteri-sql-application-eventlog.yml"
RULES_SHA = "95ae14f7e90e01a5d6d1227fa2536246725ac68c"


def assert_manual_minimized_contract(raw: str) -> None:
    assert "workflow_dispatch:" in raw
    assert "\n  push:" not in raw
    assert "\n  pull_request:" not in raw
    assert "\n  schedule:" not in raw
    assert "github.repository == 'ericson-j-santos/noteri-runtime'" in raw
    assert "github.ref == 'refs/heads/main'" in raw
    assert "github.event_name == 'workflow_dispatch'" in raw
    assert "github.actor == 'ericson-j-santos'" in raw
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in raw
    assert "timeout-minutes: 6" in raw
    assert "group: noteri-sql-application-eventlog" in raw
    assert "cancel-in-progress: false" in raw
    assert "permissions:\n  contents: read" in raw
    assert f"RULES_SHA: {RULES_SHA}" in raw
    assert raw.count("persist-credentials: false") == 2
    assert raw.count("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09") == 2
    assert "--require-runner-version-preflight" in raw
    assert "'SESSION_LAUNCH_OK'" in raw
    assert "$receipt.state_validated -ne $true" in raw
    assert "$receipt.head -ne $env:GITHUB_SHA" in raw
    assert "'--risk', '1', '--timeout', '30'" in raw
    assert raw.count("'--expected-head', $env:GITHUB_SHA") == 2
    assert "noteri_sql_application_eventlog.py" in raw
    assert "'--expected-sha', $env:GITHUB_SHA" in raw
    assert "$envelope.state_changed -ne $false" in raw
    assert "$envelope.before.head -ne $env:GITHUB_SHA" in raw
    assert "$envelope.after.head -ne $env:GITHUB_SHA" in raw
    assert "($names -join ',') -ne 'classification,date,id'" in raw
    assert "ConvertTo-Json -InputObject @($sanitized) -Compress" in raw
    assert "actions/upload-artifact" not in raw
    assert "secrets." not in raw
    assert "Get-WinEvent" not in raw
    assert "wevtutil" not in raw.lower()
    assert "EvtRender" not in raw
    assert "FormatMessage" not in raw
    assert "<Event" not in raw


def test_workflow_has_manual_minimized_governed_contract() -> None:
    assert_manual_minimized_contract(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("workflow_dispatch:", "schedule:\n    - cron: '0 * * * *'"),
        ("github.ref == 'refs/heads/main'", "github.ref != ''"),
        ("github.actor == 'ericson-j-santos'", "github.actor != ''"),
        ("runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]", "runs-on: windows-latest"),
        ("'--risk', '1', '--timeout', '30'", "'--risk', '2', '--timeout', '30'"),
        ("'--expected-head', $env:GITHUB_SHA", "'--expected-head', 'main'"),
        ("($names -join ',') -ne 'classification,date,id'", "($names.Count -lt 1)"),
        ("persist-credentials: false", "persist-credentials: true"),
    ],
)
def test_contract_rejects_broadened_or_unbound_variants(
    needle: str, replacement: str
) -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert needle in raw
    with pytest.raises(AssertionError):
        assert_manual_minimized_contract(raw.replace(needle, replacement, 1))


def test_workflow_has_no_free_form_inputs_or_persistent_activation() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    dispatch = raw.split("workflow_dispatch:", maxsplit=1)[1].split(
        "permissions:", maxsplit=1
    )[0]
    assert "inputs:" not in dispatch
    assert "schtasks" not in raw.lower()
    assert "new-service" not in raw.lower()
    assert "set-service" not in raw.lower()
    assert "docker " not in raw.lower()
    assert "sqlcmd" not in raw.lower()
    assert "invoke-sqlcmd" not in raw.lower()
    assert "certutil" not in raw.lower()
