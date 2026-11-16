#!/usr/bin/env python3
"""Read-only maintenance admission for the existing Noteri control plane.

This bridge does not install a service, grant a lease, change a worktree or
expose an apply command. A healthy Worker Pool, a Gateway reservation, and a
historical snapshot are NOT authorization to take possession of old sessions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket

import noteri_control_plane_watchdog as watchdog
import noteri_git_gateway_stderr_diagnostic as diag
import noteri_unicode_empty_directory_recovery as recovery
import noteri_worker_pool_health_owner_readonly as health
from noteri_ollama_recovery_preflight import source_sha

HEAD = re.compile(r"[0-9a-f]{40}\Z")
CORR = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
CONFIRM = "AUDIT-NOTERI-UNICODE-CONTROL-PLANE-DEV"
CONTROL_ROOT = Path("ReqSys") / "CommandGateway"
TARGETS = tuple(sorted(recovery.TARGETS))


class AdmissionBlocked(RuntimeError):
    pass


def _condition(value: bool, code: str) -> None:
    if not value:
        raise AdmissionBlocked(code)


def admission(*, target: str, state_root: Path,
              source_head: str,
              profile: str,
              host: str,
              owner_rows: list[dict],
              pool_health: dict) -> dict:
    """Independent readback; never promote read-only evidence into a lease."""
    _condition(target in recovery.TARGETS, "TARGET_NOT_ALLOWED")
    _condition(HEAD.fullmatch(source_head) is not None, "SOURCE_HEAD_INVALID")
    _condition(host.casefold() == "noteri", "WRONG_HOST")
    _condition(profile == "NORMAL", "PROFILE_NOT_NORMAL")
    _condition(not state_root.is_symlink(), "CONTROL_STATE_LINK")
    _condition(
        isinstance(owner_rows, list) and len(owner_rows) == 1
        and isinstance(owner_rows[0], dict)
        and str(owner_rows[0].get("name", "")).casefold() == "python.exe"
        and type(owner_rows[0].get("pid")) is int
        and owner_rows[0]["pid"] > 0,
        "WORKER_POOL_OWNER_NOT_UNIQUE",
    )
    _condition(
        isinstance(pool_health, dict)
        and pool_health.get("result") == "WORKER_POOL_API_HEALTHY"
        and pool_health.get("http_status") == 200
        and pool_health.get("service") == "codex-worker-pool"
        and pool_health.get("auth_configured") is True
        and pool_health.get("rules_pin_configured") is True
        and pool_health.get("storage_backend") in {"sqlite", "postgres"},
        "WORKER_POOL_UNTRUSTED",
    )
    check = diag.reservation_attestation(
        recovery.ROOT / target, state_root, recovery.EXPECTED_HEAD,
    )
    _condition(
        check.get("state") == "RESERVATION_ATTESTED_READONLY"
        and all(check.get("checks", {}).values()),
        "LEGACY_RESERVATION_NOT_ATTESTED",
    )
    pre = recovery.preview(recovery.ROOT / target, target)
    _condition(
        pre.get("result") == "RECOVERY_PREFLIGHT_ONLY"
        and pre.get("empty_directory") is True,
        "UNICODE_DIRECTORY_PREVIEW_NOT_ATTESTED",
    )
    shared = (
        pool_health.get("authority_id_present") is True
        and pool_health.get("fenced_cutover_enabled") is True
        and pool_health.get("storage_backend") == "postgres"
    )
    # A real shared Worker Pool alone still cannot revoke old Gateway sessions.
    return {
        "result": "UNICODE_MAINTENANCE_NOT_ADMITTED",
        "target": target,
        "source_sha": source_head,
        "legacy_session_reservation_valid": True,
        "empty_invalid_unicode_directory": True,
        "pool_healthy": True,
        "pool_shared_fencing_present": shared,
        "legacy_sessions_quiescence_proven": False,
        "exclusive_lease_proven": False,
        "apply_authorized": False,
        "state_changed": False,
        "next_required_capability": (
            "LEGACY_SESSION_QUIESCENCE_AND_FENCED_CLAIM"
            if shared else "SHARED_AUTHORITY_AND_LEGACY_SESSION_FENCING"
        ),
    }


def execute_through_installed_controller(
    payload: dict, *, expected_source_sha: str,
    installed_controller: object, quarantine_root: Path,
) -> dict:
    """Typed dispatch requires a separate installed/attested supervisor.

    Never expose this method as a generic local CLI command.
    An external authenticating supervisor must first halt new claims,
    quiesce old Gateway sessions and keep the fenced lease for the full call.
    """
    request = recovery.admit_typed_request(
        payload, controller_source_sha=expected_source_sha,
    )
    if (installed_controller is None
            or getattr(installed_controller, "installed_source_sha", None)
                != expected_source_sha
            or getattr(installed_controller, "legacy_sessions_quiesced", None)
                is not True
            or getattr(installed_controller, "new_claims_fenced", None)
                is not True
            or not callable(getattr(installed_controller, "exclusive_claim", None))):
        raise AdmissionBlocked("INSTALLED_FENCING_CONTROLLER_REQUIRED")
    return recovery.recover_typed_request(
        payload, controller_source_sha=expected_source_sha,
        authority=installed_controller, trusted_quarantine=quarantine_root,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        if (os.name != "nt" or socket.gethostname().casefold() != "noteri"
                or not HEAD.fullmatch(args.expected_head)
                or not CORR.fullmatch(args.correlation_id)
                or args.confirm != CONFIRM
                or source_sha(root) != args.expected_head):
            raise AdmissionBlocked("SOURCE_HOST_OR_REQUEST_UNATTESTED")
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise AdmissionBlocked("LOCAL_STATE_UNAVAILABLE")
        result = admission(
            target=args.target,
            state_root=Path(local) / CONTROL_ROOT,
            source_head=args.expected_head,
            profile=watchdog.runtime_profile(),
            host=socket.gethostname(),
            owner_rows=health.windows_owners(),
            pool_health=health.probe_health(),
        )
        result["correlation_id"] = args.correlation_id
        print(json.dumps(result, sort_keys=True))
        # Status and process code agree: a non-admitted maintenance operation
        # must never look like an executable/green dispatch to a scheduler.
        return 2
    except (AdmissionBlocked, diag.Blocked, recovery.Blocked,
            OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, AdmissionBlocked) else (
            "OPERATIONAL_PRECHECK_UNAVAILABLE"
        )
        print(json.dumps({"result": "UNICODE_MAINTENANCE_BLOCKED",
                          "reason": reason, "apply_authorized": False,
                          "state_changed": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
