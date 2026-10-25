#!/usr/bin/env python3
"""Validate sanitized Noteri credential receipt in an independent Actions job."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
KEYS = {
    "schema_version", "result", "preflight_mode", "source_sha", "workflow_sha",
    "run_id", "state_changed", "private_reference",
    "token_bytes_read_by_readback", "credential_value_exposed", "activated",
}


class CredentialArtifactBlocked(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialArtifactBlocked("duplicate_key")
        result[key] = value
    return result


def validate(path: Path, workflow_sha: str, run_id: str) -> dict:
    if not SHA40.fullmatch(workflow_sha) or not run_id.isdecimal():
        raise CredentialArtifactBlocked("identity_invalid")
    if path.is_symlink() or not path.is_file():
        raise CredentialArtifactBlocked("artifact_missing_or_link")
    data = path.read_bytes()
    if not data or len(data) > 4096:
        raise CredentialArtifactBlocked("artifact_size_invalid")
    try:
        payload = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CredentialArtifactBlocked("artifact_json_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != KEYS:
        raise CredentialArtifactBlocked("artifact_schema_invalid")
    if (payload["schema_version"] != "1"
            or payload["result"] != "PRIVATE_REFERENCE_READY"
            or payload["preflight_mode"] not in {"provision", "existing"}
            or payload["source_sha"] != SOURCE_SHA
            or payload["workflow_sha"] != workflow_sha
            or payload["run_id"] != run_id):
        raise CredentialArtifactBlocked("artifact_identity_invalid")
    if (payload["state_changed"] is not (payload["preflight_mode"] == "provision")
            or payload["private_reference"] is not True
            or payload["token_bytes_read_by_readback"] is not False
            or payload["credential_value_exposed"] is not False
            or payload["activated"] is not False):
        raise CredentialArtifactBlocked("artifact_scope_invalid")
    return {
        "result": "CREDENTIAL_READBACK_OK",
        "source_sha": SOURCE_SHA,
        "workflow_sha": workflow_sha,
        "run_id": run_id,
        "state_changed": payload["state_changed"],
        "private_reference": True,
        "activated": False,
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
        if args.source_sha != SOURCE_SHA:
            raise CredentialArtifactBlocked("source_sha_invalid")
        print(json.dumps(validate(args.evidence, args.workflow_sha, args.run_id), sort_keys=True))
        return 0
    except (OSError, CredentialArtifactBlocked) as exc:
        reason = str(exc) if isinstance(exc, CredentialArtifactBlocked) else "artifact_io_unavailable"
        print(json.dumps({"result": "CREDENTIAL_READBACK_BLOCKED", "reason": reason}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
