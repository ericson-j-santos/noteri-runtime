from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validate_noteri_worker_pool_plan_artifact import (
    ReadbackBlocked,
    validate_artifact,
)

SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"


def evidence(**overrides: object) -> dict:
    payload = {
        "result": "STAGE_PLAN_READY",
        "source_sha": SOURCE_SHA,
        "file_count": 18,
        "state_changed": False,
        "activated": False,
        "secrets_read": False,
    }
    payload.update(overrides)
    return payload


def test_independent_readback_accepts_powershell_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(evidence()).encode("utf-8"))
    receipt = validate_artifact(path, SOURCE_SHA)
    assert receipt["result"] == "PLAN_READBACK_OK"
    assert receipt["file_count"] == 18
    assert len(receipt["evidence_sha256"]) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"result": "STAGED_ONLY"},
        {"source_sha": "0" * 40},
        {"file_count": 0},
        {"file_count": True},
        {"state_changed": True},
        {"activated": True},
        {"secrets_read": True},
        {"token": "must-not-appear"},
    ],
)
def test_readback_blocks_divergence(tmp_path: Path, change: dict) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evidence(**change)), encoding="utf-8")
    with pytest.raises(ReadbackBlocked):
        validate_artifact(path, SOURCE_SHA)


def test_readback_blocks_duplicate_keys_and_link(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(
        '{"result":"STAGE_PLAN_READY","result":"STAGE_PLAN_READY"}',
        encoding="utf-8",
    )
    with pytest.raises(ReadbackBlocked):
        validate_artifact(path, SOURCE_SHA)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ReadbackBlocked):
        validate_artifact(link, SOURCE_SHA)
