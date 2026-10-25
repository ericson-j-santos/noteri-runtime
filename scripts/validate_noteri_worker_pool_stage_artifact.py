#!/usr/bin/env python3
"""Validate the sanitized native stage receipt from an independent Actions job."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_KEYS = {
    "schema_version", "stage_result", "readback_result", "source_sha",
    "file_count", "state_changed", "activated", "secrets_read",
    "workflow_sha", "run_id",
}


class StageReadbackBlocked(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise StageReadbackBlocked("duplicate_key")
        result[key] = value
    return result


def validate_artifact(
    path: Path, expected_source_sha: str, workflow_sha: str, run_id: str
) -> dict:
    if not SHA40.fullmatch(expected_source_sha) or not SHA40.fullmatch(workflow_sha):
        raise StageReadbackBlocked("expected_sha_invalid")
    if not run_id.isdecimal():
        raise StageReadbackBlocked("run_id_invalid")
    if path.is_symlink() or not path.is_file():
        raise StageReadbackBlocked("artifact_missing_or_link")
    data = path.read_bytes()
    if not data or len(data) > 4096:
        raise StageReadbackBlocked("artifact_size_invalid")
    try:
        payload = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StageReadbackBlocked("artifact_json_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != EXPECTED_KEYS:
        raise StageReadbackBlocked("artifact_schema_invalid")
    if payload["schema_version"] != "1":
        raise StageReadbackBlocked("schema_version_invalid")
    if payload["stage_result"] not in ("STAGED_ONLY", "ALREADY_STAGED"):
        raise StageReadbackBlocked("stage_result_invalid")
    if payload["readback_result"] != "ALREADY_STAGED":
        raise StageReadbackBlocked("release_readback_invalid")
    if payload["source_sha"] != expected_source_sha:
        raise StageReadbackBlocked("source_sha_mismatch")
    if payload["workflow_sha"] != workflow_sha or payload["run_id"] != run_id:
        raise StageReadbackBlocked("workflow_identity_mismatch")
    count = payload["file_count"]
    if type(count) is not int or not 1 <= count <= 800:
        raise StageReadbackBlocked("file_count_invalid")
    changed = payload["stage_result"] == "STAGED_ONLY"
    if payload["state_changed"] is not changed:
        raise StageReadbackBlocked("stage_state_mismatch")
    if payload["activated"] is not False or payload["secrets_read"] is not False:
        raise StageReadbackBlocked("stage_scope_violation")
    return {
        "result": "STAGE_READBACK_OK",
        "stage_result": payload["stage_result"],
        "readback_result": payload["readback_result"],
        "source_sha": expected_source_sha,
        "file_count": count,
        "state_changed": changed,
        "activated": False,
        "secrets_read": False,
        "workflow_sha": workflow_sha,
        "run_id": run_id,
        "evidence_sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        receipt = validate_artifact(
            args.evidence, args.source_sha, args.workflow_sha, args.run_id
        )
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (OSError, StageReadbackBlocked) as exc:
        reason = str(exc) if isinstance(exc, StageReadbackBlocked) else "artifact_io_unavailable"
        print(json.dumps({"result": "STAGE_READBACK_BLOCKED", "reason": reason}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
