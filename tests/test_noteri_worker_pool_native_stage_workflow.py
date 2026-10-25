from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validate_noteri_worker_pool_stage_artifact import (
    StageReadbackBlocked,
    validate_artifact,
)

SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
WORKFLOW_SHA = "a" * 40
RUN_ID = "12345"
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/noteri-worker-pool-native-stage.yml"


def receipt(**overrides: object) -> dict:
    payload = {
        "schema_version": "1",
        "stage_result": "STAGED_ONLY",
        "readback_result": "ALREADY_STAGED",
        "source_sha": SOURCE_SHA,
        "file_count": 38,
        "state_changed": True,
        "activated": False,
        "secrets_read": False,
        "workflow_sha": WORKFLOW_SHA,
        "run_id": RUN_ID,
    }
    payload.update(overrides)
    return payload


def test_stage_receipt_accepts_first_stage_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(receipt()).encode("utf-8"))
    first = validate_artifact(path, SOURCE_SHA, WORKFLOW_SHA, RUN_ID)
    assert first["result"] == "STAGE_READBACK_OK"
    assert first["state_changed"] is True
    assert len(first["evidence_sha256"]) == 64
    path.write_text(
        json.dumps(receipt(stage_result="ALREADY_STAGED", state_changed=False)),
        encoding="utf-8",
    )
    replay = validate_artifact(path, SOURCE_SHA, WORKFLOW_SHA, RUN_ID)
    assert replay["result"] == "STAGE_READBACK_OK"
    assert replay["state_changed"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"stage_result": "STAGE_PLAN_READY"},
        {"readback_result": "STAGE_PLAN_READY"},
        {"source_sha": "0" * 40},
        {"file_count": 0},
        {"file_count": True},
        {"state_changed": False},
        {"activated": True},
        {"secrets_read": True},
        {"workflow_sha": "0" * 40},
        {"run_id": "999"},
        {"token": "forbidden"},
    ],
)
def test_stage_receipt_rejects_divergence(tmp_path: Path, change: dict) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(receipt(**change)), encoding="utf-8")
    with pytest.raises(StageReadbackBlocked):
        validate_artifact(path, SOURCE_SHA, WORKFLOW_SHA, RUN_ID)


def test_stage_receipt_rejects_duplicate_keys_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text('{"run_id":"12345","run_id":"12345"}', encoding="utf-8")
    with pytest.raises(StageReadbackBlocked):
        validate_artifact(path, SOURCE_SHA, WORKFLOW_SHA, RUN_ID)
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    with pytest.raises(StageReadbackBlocked):
        validate_artifact(alias, SOURCE_SHA, WORKFLOW_SHA, RUN_ID)


def test_stage_workflow_is_manual_bounded_and_has_physical_readback() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in raw
    assert "\n  push:" not in raw
    assert raw.count("github.ref == 'refs/heads/main'") == 2
    assert "github.actor == 'ericson-j-santos'" in raw
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in raw
    assert raw.count("persist-credentials: false") == 4
    assert "'--risk', '2'" in raw
    assert "'--mode', 'stage', '--confirm', 'STAGE-NOTERI-WORKER-POOL'" in raw
    assert "'--risk', '1'" in raw
    assert "'--mode', 'plan'" in raw
    assert "$observed.result -ne 'ALREADY_STAGED'" in raw
    assert "needs: native-stage" in raw
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in raw
    assert "validate_noteri_worker_pool_stage_artifact.py" in raw
    assert "schtasks " not in raw.lower()
    assert "docker " not in raw.lower()
    assert "actions: write" not in raw
