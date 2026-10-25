from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/noteri-worker-pool-native-plan.yml"


def workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def assert_readonly_contract(text: str) -> None:
    assert "workflow_dispatch:" in text
    assert "branches: [main]" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "github.repository == 'ericson-j-santos/noteri-runtime'" in text
    assert "github.actor == 'ericson-j-santos'" in text
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in text
    assert "permissions:\n  contents: read" in text
    assert "21fd68dec6f0da92b3e7da201463401ac5429d64" in text
    assert "4e6091a133f8d7d157abe6f83c31ca597812e0a4" in text
    assert "repository: ericson-j-santos/engineering-worker-pool" in text
    assert "path: _worker_pool" in text
    assert text.count("persist-credentials: false") == 4
    assert "SESSION_LAUNCH_OK" in text
    assert "--require-runner-version-preflight" in text
    assert "command_gateway.py" in text
    assert "'--risk', '1'" in text
    assert "noteri_worker_pool_native_stage.py" in text
    assert "'--mode', 'plan'" in text
    assert "state_changed -ne $false" in text
    assert "activated -ne $false" in text
    assert "secrets_read -ne $false" in text
    assert "noteri-worker-pool-plan-" in text
    assert "independent-readback:" in text
    assert "needs: native-plan" in text
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in text
    assert "validate_noteri_worker_pool_plan_artifact.py" in text
    assert "'--mode', 'stage'" not in text
    assert "--confirm" not in text
    assert "sudo" not in text.lower()
    assert "docker " not in text.lower()
    assert "schtasks " not in text.lower()
    assert "powershell -command" not in text.lower()
    assert "secrets." not in text
    assert "actions: write" not in text


def test_stage_plan_workflow_is_bounded_and_read_only() -> None:
    assert_readonly_contract(workflow())


@pytest.mark.parametrize(
    "before,after",
    [
        ("'--mode', 'plan'", "'--mode', 'stage'"),
        ("'--risk', '1'", "'--risk', '3'"),
        ("github.ref == 'refs/heads/main'", "github.ref != 'refs/heads/main'"),
        ("persist-credentials: false", "persist-credentials: true"),
        ("'--mode', 'plan'", "'--mode', 'plan', '--confirm', 'STAGE-NOTERI-WORKER-POOL'"),
    ],
)
def test_negative_contract_rejects_unsafe_workflow_changes(
    before: str, after: str
) -> None:
    raw = workflow()
    assert before in raw
    with pytest.raises(AssertionError):
        assert_readonly_contract(raw.replace(before, after, 1))
