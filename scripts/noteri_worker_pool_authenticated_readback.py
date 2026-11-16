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
import xml.etree.ElementTree as ET

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


def xml_difference_fields(raw: bytes, python: Path, runner: Path, user: str) -> list[str]:
    """Read XML values but reveal ONLY public, bounded field names, never values."""
    if not raw or len(raw) > 131072:
        return ["xml_unavailable"]
    try:
        try:
            doc = ET.fromstring(raw)
        except ET.ParseError:
            # schtasks.exe can emit UTF-8 content with a UTF-16 declaration.
            if not (raw.startswith(b'<?xml ') and
                    b'encoding="UTF-16"' in raw[:128]):
                return ["xml_parse"]
            doc = ET.fromstring(raw.replace(
                b'encoding="UTF-16"', b'encoding="UTF-8"', 1))
        ns = {"t": activation.NS}
        def field(path: str) -> str:
            return doc.findtext(path, default="", namespaces=ns)
        def expected(path: str, target: str, label: str) -> list[str]:
            return [] if field(path) == target else [label]
        differences = []
        observed_user = field("t:Principals/t:Principal/t:UserId")
        # Avoid showing a SID, account name, or normalized principal value.
        user_matches = observed_user.casefold() == user.casefold()
        if observed_user and not user_matches:
            try:
                expected_sid = activation.account_sid(user)
                user_matches = (observed_user == expected_sid
                                or activation.account_sid(observed_user) == expected_sid)
            except Exception:
                pass
        if not user_matches:
            differences.append("principal")
        for path, value, label in (
            ("t:Principals/t:Principal/t:LogonType", "S4U", "logon_type"),
            ("t:Principals/t:Principal/t:RunLevel", "LeastPrivilege", "run_level"),
            ("t:Triggers/t:BootTrigger/t:Enabled", "true", "boot_trigger"),
            ("t:Settings/t:Enabled", "true", "task_enabled"),
            ("t:Actions/t:Exec/t:Command", str(python), "action_path"),
            ("t:Actions/t:Exec/t:Arguments", f'-B "{runner}"', "action_arguments"),
            ("t:Actions/t:Exec/t:WorkingDirectory", str(runner.parent),
             "action_working_directory"),
        ):
            differences.extend(expected(path, value, label))
        return sorted(set(differences))
    except (ET.ParseError, ValueError, TypeError, OSError):
        return ["xml_parse"]


def xml_optional_field_states(raw: bytes, fields: list[str]) -> dict[str, str]:
    """Only tell whether a required XML element is missing or has another value."""
    mapping = {
        "run_level": "t:Principals/t:Principal/t:RunLevel",
        "boot_trigger": "t:Triggers/t:BootTrigger/t:Enabled",
        "task_enabled": "t:Settings/t:Enabled",
    }
    try:
        try:
            doc = ET.fromstring(raw)
        except ET.ParseError:
            if not (raw.startswith(b'<?xml ') and
                    b'encoding="UTF-16"' in raw[:128]):
                return {k: "unparsed" for k in fields if k in mapping}
            doc = ET.fromstring(raw.replace(
                b'encoding="UTF-16"', b'encoding="UTF-8"', 1))
        return {
            k: ("missing" if doc.find(mapping[k], namespaces={"t": activation.NS}) is None
                else "different")
            for k in fields if k in mapping
        }
    except (ET.ParseError, ValueError, TypeError):
        return {k: "unparsed" for k in fields if k in mapping}


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
        # The only two admitted release shapes are:
        # (1) the previously observed single generated cache; or
        # (2) the immutable release restored to exact manifest contents with
        #     that exact bytecode preserved in hashed same-volume quarantine.
        # Never accept a missing cache with no independently verified backup.
        counts = audit.get("counts", {})
        official_files_valid = (
            audit.get("source_identity_verified") is True
            and audit.get("installed_manifest") == "valid"
            and audit.get("expected_file_count") == 38
            and all(counts.get(name) == 0 for name in (
                "missing", "hash_mismatch", "unsafe", "manifest_keys_missing",
                "manifest_keys_extra", "manifest_hash_mismatch"))
            and audit.get("manifest_metadata_mismatch") == []
        )
        old_shape = (
            audit.get("result") == "RELEASE_MISMATCH"
            and audit.get("extra") == [cache.CACHE_LABEL]
            and counts.get("extra") == 1
        )
        restored_shape = (
            audit.get("result") == "RELEASE_INTACT"
            and audit.get("extra") == []
            and counts.get("extra") == 0
        )
        if not official_files_valid or not (old_shape or restored_shape):
            return _fail(result, "BLOCKED_RELEASE")
        if restored_shape:
            try:
                expected_backup = (
                    local / cache.QUARANTINE_FOLDER
                    / (cache.CACHE_RELATIVE.name + "."
                       + cache.KNOWN_CACHE_SHA256 + ".quarantined")
                )
                backups = cache._backups(local / cache.QUARANTINE_FOLDER)
                if backups != [(expected_backup, cache.KNOWN_CACHE_SHA256)]:
                    return _fail(result, "BLOCKED_QUARANTINE_BACKUP")
            except (OSError, ValueError, TypeError, cache.Blocked):
                return _fail(result, "BLOCKED_QUARANTINE_BACKUP")
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
        if task.returncode != 0:
            return _fail(result, "BLOCKED_TASK_QUERY")
        if len(task.stdout) > 131072:
            return _fail(result, "BLOCKED_TASK_SIZE")
        xml_matches = activation.task_matches(task.stdout, python, runner, user_id)
        package = root / "control" / control.TARGET_NAME
        if not control.verify(package):
            return _fail(result, "BLOCKED_CONTROL_PACKAGE")
        task_diffs = activation.task_com_mismatches(python, runner, user_id, package)
        if task_diffs:
            permitted = {"principal", "logon_type", "run_level", "boot_trigger",
                         "boot_delay", "trigger_count", "action_count", "action_path",
                         "action_arguments", "action_working_directory", "task_path",
                         "task_enabled", "multiple_instances", "execution_time_limit",
                         "com_readback"}
            result["task_difference_fields"] = sorted({
                v if v in permitted or v.startswith("settings_") and
                v in ("settings_Enabled", "settings_StartWhenAvailable",
                      "settings_DisallowStartIfOnBatteries",
                      "settings_StopIfGoingOnBatteries") else "other"
                for v in task_diffs
            })
            return _fail(result, "BLOCKED_TASK_COM")
        result["task_com_verified"] = True
        if not xml_matches:
            fields = xml_difference_fields(task.stdout, python, runner, user_id)
            states = xml_optional_field_states(task.stdout, fields)
            # schtasks /XML may omit three default-valued elements that the
            # independent COM task definition explicitly attests. Never accept
            # an explicit conflicting XML value or another missing field.
            implicit = {"run_level", "boot_trigger", "task_enabled"}
            if (not fields or not set(fields).issubset(implicit)
                    or any(states.get(field) != "missing" for field in fields)):
                result["xml_difference_fields"] = fields
                result["xml_field_states"] = states
                return _fail(result, "BLOCKED_TASK_XML")
            result["task_defaults_attested_by_com"] = sorted(fields)
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
