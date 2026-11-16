#!/usr/bin/env python3
"""Read-only, owner-pinned Worker Pool task and authenticated contract attestation.

Only the already-qualified local loopback API and the existing protected token
are allowed. The token is opened *after* independent task/process attribution;
no bytes, paths or exception details containing secrets are emitted. This probe
never creates a file, changes a task or modifies the Worker Pool release.
"""
from __future__ import annotations

import getpass
import json
import os
import socket
from pathlib import Path

from scripts import noteri_worker_pool_native_activation as activation
from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_release_audit as release_audit
from scripts import noteri_worker_pool_cache_quarantine as cache
from scripts import noteri_worker_pool_native_venv as venv
from scripts import noteri_worker_pool_control_package as control

SOURCE_SHA = reference.SOURCE_SHA
BASE = {"schema_version": "1", "source_sha": SOURCE_SHA, "result": "BLOCKED",
        "task_s4u_verified": False, "listener_attributed": False,
        "negative_auth_verified": False, "contract_authenticated": False,
        "contract_replay_verified": False, "token_bytes_read": False,
        "token_disclosed": False, "state_changed": False, "activated": False}


def _fail(result: dict, reason: str) -> dict:
    result["result"] = reason
    return result


def attest(*, local: Path, host: str, platform: str, user: str) -> dict:
    result = dict(BASE)
    if host.casefold() != "noteri" or platform != "nt":
        return _fail(result, "BLOCKED_HOST")
    source = (local / "ReqSys" / "NoteriRuntimeRunner" / "_work" /
              "noteri-runtime" / "noteri-runtime" / "_worker_pool")
    root, release, env_root = venv._paths(local)
    runner = root / "bin" / activation.RUNNER_FILES[0]
    python = venv._python(env_root)
    token_path = local / reference.TOKEN_RELATIVE
    try:
        profile = json.loads((local / reference.PROFILE_RELATIVE).read_text(
            encoding="utf-8")).get("profile")
        if profile != "NORMAL":
            return _fail(result, "BLOCKED_PROFILE")
        for fixed in (source, release, root / "bin", python, runner, token_path):
            stage.ensure_no_link_components(fixed)
        audit = release_audit.audit(
            source=source, release=release, hostname=host, platform=platform,
            profile=profile, inspect_git=stage.git_identity)
        if (audit.get("source_identity_verified") is not True or
                audit.get("result") != "RELEASE_MISMATCH" or
                audit.get("expected_file_count") != 38 or
                audit.get("extra") != [cache.CACHE_LABEL] or
                audit.get("counts", {}).get("extra") != 1 or
                any(audit["counts"].get(name) != 0 for name in (
                    "missing", "hash_mismatch", "unsafe", "manifest_keys_missing",
                    "manifest_keys_extra", "manifest_hash_mismatch")) or
                audit.get("manifest_metadata_mismatch") != []):
            # The cache is an explicit known exception solely for observation.
            # The normal immutable-stage integrity gate remains unchanged.
            return _fail(result, "BLOCKED_RELEASE")
        for name in activation.RUNNER_FILES:
            installed = root / "bin" / name
            source_file = Path(__file__).resolve().parent / name
            stage.ensure_no_link_components(installed)
            if (not installed.is_file() or not source_file.is_file() or
                    activation.sha256(installed) != activation.sha256(source_file)):
                return _fail(result, "BLOCKED_RUNTIME_SOURCE")
        if not python.is_file():
            return _fail(result, "BLOCKED_RUNTIME_PYTHON")
        user_id = f"{host}\\{user}"
        task = activation.schtasks("/Query", "/TN", activation.TASK_NAME, "/XML")
        if (task.returncode != 0 or len(task.stdout) > 131072 or
                not activation.task_matches(task.stdout, python, runner, user_id)):
            return _fail(result, "BLOCKED_TASK_XML")
        if not control.verify(root / "control" / control.TARGET_NAME):
            return _fail(result, "BLOCKED_CONTROL_PACKAGE")
        if activation.task_com_mismatches(
                python, runner, user_id, root / "control" / control.TARGET_NAME):
            return _fail(result, "BLOCKED_TASK_COM")
        result["task_s4u_verified"] = True
        if not activation.listener_owned_by_task(python, runner):
            return _fail(result, "BLOCKED_PROCESS_ATTRIBUTION")
        result["listener_attributed"] = True
        status, health = activation.http_status("/health")
        if (status != 200 or not isinstance(health, dict)
                or health.get("service") != "codex-worker-pool"
                or health.get("status") != "healthy"
                or health.get("auth_configured") is not True
                or health.get("expected_rules_sha_configured") is not True
                or health.get("contract_version") != "v1"):
            return _fail(result, "BLOCKED_HEALTH")
        negative, _ = activation.http_status("/v1/contract", "invalid-attestation-control")
        if negative != 401:
            return _fail(result, "BLOCKED_NEGATIVE_AUTH")
        result["negative_auth_verified"] = True
        if not activation.listener_owned_by_task(python, runner):
            return _fail(result, "BLOCKED_PROCESS_DRIFT")
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
        secure = reference._load_secure_file(release, manifest)
        if not token_path.is_file():
            return _fail(result, "BLOCKED_TOKEN_REFERENCE")
        fd = secure.open_private_read(token_path)
        token = None
        try:
            secure.validate_private_fd(fd)
            if not secure.path_matches_fd(fd, token_path, private=True):
                return _fail(result, "BLOCKED_TOKEN_IDENTITY")
            raw = os.read(fd, 257)
            result["token_bytes_read"] = True
            if len(raw) > 256:
                return _fail(result, "BLOCKED_TOKEN_SIZE")
            token = raw.decode("utf-8").strip()
            if not 24 <= len(token) <= 256:
                return _fail(result, "BLOCKED_TOKEN_FORMAT")
        finally:
            os.close(fd)
        code, descriptor = activation.http_status("/v1/contract", token)
        if (code != 200 or not isinstance(descriptor, dict)
                or descriptor.get("contract_name") != "engineering-worker-pool"
                or descriptor.get("contract_version") != "v1"):
            return _fail(result, "BLOCKED_AUTH_CONTRACT")
        result["contract_authenticated"] = True
        if not activation.listener_owned_by_task(python, runner):
            return _fail(result, "BLOCKED_PROCESS_DRIFT")
        replay_code, replay = activation.http_status("/v1/contract", token)
        if replay_code != 200 or replay != descriptor:
            return _fail(result, "BLOCKED_CONTRACT_REPLAY")
        result["contract_replay_verified"] = True
        result["result"] = "AUTHENTICATED_READBACK_OK"
        return result
    except Exception:
        # Never emit the underlying exception (could contain a credential,
        # security descriptor, account name or private filesystem path).
        return _fail(result, "BLOCKED_READBACK_UNAVAILABLE")


def main() -> int:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        outcome = _fail(dict(BASE), "BLOCKED_LOCALAPPDATA")
    else:
        outcome = attest(local=Path(local), host=socket.gethostname(),
                         platform=os.name, user=getpass.getuser())
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["result"] == "AUTHENTICATED_READBACK_OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
