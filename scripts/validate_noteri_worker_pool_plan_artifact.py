#!/usr/bin/env python3
"""Independently validate the sanitized Noteri Worker Pool plan artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_KEYS = {
    "result", "source_sha", "file_count", "state_changed",
    "activated", "secrets_read",
}


class ReadbackBlocked(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ReadbackBlocked("duplicate_key")
        result[key] = value
    return result


def validate_artifact(path: Path, expected_source_sha: str) -> dict:
    if not SHA40.fullmatch(expected_source_sha):
        raise ReadbackBlocked("expected_source_sha_invalid")
    if path.is_symlink() or not path.is_file():
        raise ReadbackBlocked("artifact_missing_or_link")
    data = path.read_bytes()
    if not data or len(data) > 4096:
        raise ReadbackBlocked("artifact_size_invalid")
    try:
        payload = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReadbackBlocked("artifact_json_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != EXPECTED_KEYS:
        raise ReadbackBlocked("artifact_schema_invalid")
    if payload["result"] != "STAGE_PLAN_READY":
        raise ReadbackBlocked("plan_result_invalid")
    if payload["source_sha"] != expected_source_sha:
        raise ReadbackBlocked("source_sha_mismatch")
    count = payload["file_count"]
    if type(count) is not int or not 1 <= count <= 800:
        raise ReadbackBlocked("file_count_invalid")
    if any(payload[key] is not False for key in ("state_changed", "activated", "secrets_read")):
        raise ReadbackBlocked("read_only_invariant_failed")
    return {
        "result": "PLAN_READBACK_OK",
        "source_sha": expected_source_sha,
        "file_count": count,
        "state_changed": False,
        "activated": False,
        "secrets_read": False,
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
        if not SHA40.fullmatch(args.workflow_sha) or not args.run_id.isdecimal():
            raise ReadbackBlocked("workflow_identity_invalid")
        receipt = validate_artifact(args.evidence, args.source_sha)
        receipt["workflow_sha"] = args.workflow_sha
        receipt["run_id"] = args.run_id
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (OSError, ReadbackBlocked) as exc:
        reason = str(exc) if isinstance(exc, ReadbackBlocked) else "artifact_io_unavailable"
        print(json.dumps({"result": "PLAN_READBACK_BLOCKED", "reason": reason}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
