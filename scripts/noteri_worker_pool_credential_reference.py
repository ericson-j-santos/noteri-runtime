#!/usr/bin/env python3
"""Read-only qualification of the dedicated Noteri Worker Pool token reference.

The token bytes are never read. The staged shared implementation verifies the
file handle and NTFS ACL under the same identity that runs this probe.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
from pathlib import Path

from scripts import noteri_worker_pool_native_stage as stage

SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
TOKEN_RELATIVE = Path("ReqSys") / "NoteriWorkerPool" / "credentials" / "api-token.txt"
RELEASES_RELATIVE = Path("ReqSys") / "NoteriWorkerPool" / "releases"
PROFILE_RELATIVE = Path("ReqSys") / "TodoGlobal24x7" / "host-profile.json"


def _receipt(result: str, *, private_reference: bool = False) -> dict:
    return {
        "schema_version": "1",
        "result": result,
        "source_sha": SOURCE_SHA,
        "release_verified": result in {
            "BLOCKED_TOKEN_REFERENCE", "BLOCKED_TOKEN_FILE", "REFERENCE_PRIVATE_UNREAD",
        },
        "private_reference": private_reference,
        "token_bytes_read": False,
        "activated": False,
        "state_changed": False,
    }


def _load_secure_file(release: Path, manifest: dict):
    relative = "app/secure_file.py"
    expected = manifest.get("files", {}).get(relative)
    path = release / relative
    if not isinstance(expected, str) or stage.file_sha256(path) != expected:
        raise stage.StageBlocked("release_secure_file_invalid")
    spec = importlib.util.spec_from_file_location("noteri_staged_secure_file", path)
    if spec is None or spec.loader is None:
        raise stage.StageBlocked("release_secure_file_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def qualify(*, localappdata: Path, hostname: str, profile: str,
            platform: str, secure_module=None) -> dict:
    if platform != "nt" or hostname.casefold() != "noteri" or profile != "NORMAL":
        return _receipt("BLOCKED_HOST")
    release = localappdata / RELEASES_RELATIVE / SOURCE_SHA
    token_path = localappdata / TOKEN_RELATIVE
    try:
        stage.ensure_no_link_components(release)
        stage.ensure_no_link_components(token_path)
        manifest_path = release / "manifest.json"
        if not manifest_path.is_file() or stage.is_link(manifest_path):
            return _receipt("BLOCKED_RELEASE")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict)
                or manifest.get("source_sha") != SOURCE_SHA
                or manifest.get("source_repo") != stage.EXPECTED_REPO
                or manifest.get("kind") != "noteri_worker_pool_stage_only"
                or manifest.get("activated") is not False
                or not stage.validate_staged(release, manifest)):
            return _receipt("BLOCKED_RELEASE")
        if not token_path.exists():
            return _receipt("BLOCKED_TOKEN_REFERENCE")
        if not token_path.is_file() or stage.is_link(token_path):
            return _receipt("BLOCKED_TOKEN_FILE")
        secure = secure_module or _load_secure_file(release, manifest)
        fd = secure.open_private_read(token_path)
        try:
            secure.validate_private_fd(fd)
            if not secure.path_matches_fd(fd, token_path, private=True):
                return _receipt("BLOCKED_TOKEN_FILE")
        finally:
            os.close(fd)
        return _receipt("REFERENCE_PRIVATE_UNREAD", private_reference=True)
    except (OSError, ValueError, TypeError, stage.StageBlocked):
        return _receipt("BLOCKED_REFERENCE_INTEGRITY")
    except Exception:
        # SecureFileError is loaded from a pinned release module. Do not emit
        # exception text, private paths, ACL principals or credential metadata.
        return _receipt("BLOCKED_REFERENCE_INTEGRITY")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        payload = _receipt("BLOCKED_HOST")
    else:
        profile_path = Path(local) / PROFILE_RELATIVE
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8")).get("profile")
        except (OSError, ValueError, AttributeError):
            profile = None
        payload = qualify(
            localappdata=Path(local), hostname=socket.gethostname(),
            profile=profile, platform=os.name,
        )
    print(json.dumps(payload, sort_keys=True))
    if payload["result"] == "REFERENCE_PRIVATE_UNREAD":
        return 0
    return 0 if args.preflight and payload["result"] == "BLOCKED_TOKEN_REFERENCE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
