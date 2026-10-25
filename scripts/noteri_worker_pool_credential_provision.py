#!/usr/bin/env python3
"""Provision one dedicated Noteri Worker Pool API credential at a fixed path.

This command is Risk3. It never prints the credential, changes another
authority, starts a service, or modifies the staged release.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
from pathlib import Path

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as reference

CONFIRM = "PROVISION-NOTERI-WORKER-POOL-CREDENTIAL"
EXPECTED_REPOSITORY = "ericson-j-santos/noteri-runtime"


def _receipt(result: str, *, changed: bool = False, readback: bool = False) -> dict:
    return {
        "schema_version": "1",
        "result": result,
        "source_sha": reference.SOURCE_SHA,
        "state_changed": changed,
        "credential_readback": readback,
        "credential_value_exposed": False,
        "activated": False,
    }


def provision(*, localappdata: Path, hostname: str, profile: str, platform: str,
              confirm: str, secure_module=None, token_factory=secrets.token_urlsafe) -> dict:
    if confirm != CONFIRM or platform != "nt" or hostname.casefold() != "noteri" or profile != "NORMAL":
        return _receipt("BLOCKED_CONTEXT")
    observed = reference.qualify(
        localappdata=localappdata, hostname=hostname, profile=profile,
        platform=platform, secure_module=secure_module,
    )
    if observed["result"] == "REFERENCE_PRIVATE_UNREAD":
        release = localappdata / reference.RELEASES_RELATIVE / reference.SOURCE_SHA
        token_path = localappdata / reference.TOKEN_RELATIVE
        try:
            manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
            secure = secure_module or reference._load_secure_file(release, manifest)
            fd = secure.open_private_read(token_path)
            try:
                with os.fdopen(fd, "rb", closefd=False) as source:
                    existing = source.read(130)
                secure.validate_private_fd(fd)
                if not secure.path_matches_fd(fd, token_path, private=True):
                    return _receipt("BLOCKED_PREFLIGHT")
                if re.fullmatch(rb"[A-Za-z0-9_-]{48,128}\n?", existing) is None:
                    return _receipt("BLOCKED_PREFLIGHT")
            finally:
                os.close(fd)
            return _receipt("ALREADY_PROVISIONED", readback=True)
        except Exception:
            return _receipt("BLOCKED_PREFLIGHT")
    if observed["result"] != "BLOCKED_TOKEN_REFERENCE":
        return _receipt("BLOCKED_PREFLIGHT")
    release = localappdata / reference.RELEASES_RELATIVE / reference.SOURCE_SHA
    token_path = localappdata / reference.TOKEN_RELATIVE
    created = False
    parent_existed = token_path.parent.exists()
    try:
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
        secure = secure_module or reference._load_secure_file(release, manifest)
        stage.ensure_no_link_components(token_path)
        value = token_factory(48)
        if (not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{48,128}", value) is None):
            return _receipt("BLOCKED_GENERATOR")
        encoded = (value + "\n").encode("ascii")
        token_path.parent.mkdir(parents=True, exist_ok=True)
        stage.ensure_no_link_components(token_path)
        try:
            fd = secure.open_exclusive(token_path)
        except FileExistsError:
            return _receipt("BLOCKED_CONCURRENT", changed=not parent_existed)
        created = True
        with os.fdopen(fd, "wb") as target:
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
            secure.validate_private_fd(target.fileno())
        read_fd = secure.open_private_read(token_path)
        try:
            with os.fdopen(read_fd, "rb", closefd=False) as source:
                observed_bytes = source.read(129)
            secure.validate_private_fd(read_fd)
            if not secure.path_matches_fd(read_fd, token_path, private=True):
                return _receipt("BLOCKED_READBACK", changed=True)
            if observed_bytes != encoded:
                return _receipt("BLOCKED_READBACK", changed=True)
        finally:
            os.close(read_fd)
        return _receipt("CREDENTIAL_PROVISIONED", changed=True, readback=True)
    except Exception:
        # Preserve an uncertain newly created file for explicit reconciliation.
        # Never publish exception text, ACL principals, paths or token bytes.
        return _receipt("BLOCKED_PROVISION_OR_READBACK", changed=created or (not parent_existed and token_path.parent.exists()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    env = os.environ
    if (env.get("GITHUB_ACTIONS") != "true"
            or env.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY
            or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("GITHUB_ACTOR") != "ericson-j-santos"
            or not env.get("LOCALAPPDATA")):
        payload = _receipt("BLOCKED_CONTEXT")
    else:
        local = Path(env["LOCALAPPDATA"])
        profile_path = local / reference.PROFILE_RELATIVE
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8")).get("profile")
        except (OSError, ValueError, AttributeError):
            profile = None
        payload = provision(
            localappdata=local, hostname=socket.gethostname(),
            profile=profile, platform=os.name, confirm=args.confirm,
        )
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["result"] in {"CREDENTIAL_PROVISIONED", "ALREADY_PROVISIONED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
