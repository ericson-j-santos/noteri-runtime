#!/usr/bin/env python3
"""Fixed-target in-place maintenance for an existing Noteri Worker Pool S4U task.

Not a bootstrap or task installer. The registered task and its principal, XML,
ACLs, credential reference and immutable release must be preserved. Operate
ONLY through the already-approved Session Launcher and Command Gateway.
No claim, worker enrollment, queue mutation, credential or network fallback.
Apply is additionally denied without a separate, exact SHA-bound authorization
in the trusted gateway environment; a chat's old SHA is never inherited.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import site
import socket
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from scripts import noteri_worker_pool_native_activation as activation
from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_native_venv as venv
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_cache_quarantine as cache
from scripts import noteri_worker_pool_release_audit as release_audit
from scripts import noteri_worker_pool_queue_readonly as queue
from scripts import noteri_worker_pool_rules_pin_sync as rules_pin
from scripts import noteri_worker_pool_authenticated_readback as authenticated
from scripts import noteri_worker_pool_control_package as control

CONFIRM = "MAINTAIN-EXISTING-NOTERI-WORKER-POOL-API"
SCHEMA = "1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
ALLOWED_ORIGIN = {"https://github.com/ericson-j-santos/noteri-runtime",
                  "https://github.com/ericson-j-santos/noteri-runtime.git"}
OLD_RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
CACHE_SHA256 = cache.KNOWN_CACHE_SHA256
RUNNER = "noteri_worker_pool_api_runner.py"
MAX_XML = 131072
MAX_DB = 1_073_741_824


class MaintenanceBlocked(RuntimeError):
    """Return bounded codes only, never OS stderr, paths or credentials."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise MaintenanceBlocked(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked(path: Path) -> Path:
    stage.ensure_no_link_components(path)
    return path


def git_identity(root: Path) -> tuple[str, str, str]:
    try:
        def call(*args: str) -> str:
            r = subprocess.run(
                ["git", "-C", str(root), *args], check=False,
                capture_output=True, timeout=12, text=True,
                env={"PATH": os.environ.get("PATH", os.defpath),
                     "GIT_CONFIG_SYSTEM": os.devnull,
                     "GIT_CONFIG_GLOBAL": os.devnull,
                     "GIT_TERMINAL_PROMPT": "0"},
            )
            need(r.returncode == 0 and len(r.stdout) < 4096,
                 "checkout_git_unavailable")
            return r.stdout.strip()
        return (call("rev-parse", "HEAD"), call("remote", "get-url", "origin"),
                call("status", "--porcelain", "--untracked-files=all"))
    except (OSError, subprocess.TimeoutExpired):
        raise MaintenanceBlocked("checkout_git_unavailable") from None


def task_xml() -> bytes:
    result = activation.schtasks("/Query", "/TN", activation.TASK_NAME, "/XML")
    need(result.returncode == 0 and 100 < len(result.stdout) <= MAX_XML,
         "registered_task_unverified")
    return bytes(result.stdout)


def stopped_task_registered(local: Path) -> bool:
    """Task must STILL EXIST, have zero instances, and port must be absent.

    The old cache capability incorrectly required the task to be UNREGISTERED.
    COM verifies zero running instances without changing principal/registration.
    """
    try:
        root, _, _ = venv._paths(local)
        package = root / "control" / control.TARGET_NAME
        need(control.verify(package), "control_package_unverified")
        site.addsitedir(str(package))
        import win32com.client  # type: ignore
        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        task = service.GetFolder(r"\Automation").GetTask("NoteriWorkerPoolApi")
        return int(task.GetInstances(0).Count) == 0 and activation.listener_absent() is True
    except Exception:
        return False


def queue_safe(local: Path) -> dict[str, Any]:
    db = checked(local / "ReqSys" / "NoteriWorkerPool" / "data" / "pool.db")
    result = queue.inspect_database(db, now=__import__("datetime").datetime.now(
        __import__("datetime").timezone.utc))
    sample = result.get("queued_task_sample")
    counts = result.get("queue_counts")
    need(result.get("result") == "READ_ONLY_QUEUE_AUDIT_OK"
         and result.get("registered_workers") == 0
         and result.get("workers_heartbeat_within_90s") == 0
         and result.get("tasks_active_states") == 0
         and result.get("leases_unexpired") == 0
         and result.get("active_states_expired_or_missing_lease") == 0
         and result.get("open_attempt_records") == 0
         and result.get("unresolved_checkpoint_effects") == 0
         and result.get("fenced_cutover_enabled") is False
         and result.get("synthetic_smoke_lane_disabled") is True
         and result.get("synthetic_smoke_identity_consistent") is True
         and type(counts) is dict and counts.get("queued") == 1
         and sum(counts.values()) == 1
         and type(sample) is list and len(sample) == 1
         and sample[0]["repository"] == "ericson-j-santos/codex-worker-pool-smoke"
         and sample[0]["issue_number"] == 1914
         and sample[0]["fencing_required"] is False,
         "queue_not_exclusively_idle")
    return {"task_count": 1, "workers": 0, "fenced_cutover": False,
            "synthetic_never_claim": True}


def selected_paths(local: Path) -> dict[str, Path]:
    root, release, venv_root = venv._paths(local)
    return {
        "runtime": root,
        "release": checked(release),
        "source_pool": checked(
            local / "ReqSys" / "NoteriRuntimeRunner" / "_work"
            / "noteri-runtime" / "noteri-runtime" / "_worker_pool"),
        "runner": checked(root / "bin" / RUNNER),
        "stage_runner": checked(root / "bin" / "noteri_worker_pool_native_stage.py"),
        "python": checked(venv._python(venv_root)),
        "token": checked(local / reference.TOKEN_RELATIVE),
        "database": checked(root / "data" / "pool.db"),
        "quarantine": checked(local / cache.QUARANTINE_FOLDER),
        "maintenance": checked(root / "maintenance"),
    }


def approval_required(expected_sha: str, *, confirm: str) -> None:
    need(confirm == CONFIRM
         and type(expected_sha) is str and bool(SHA40.fullmatch(expected_sha))
         and os.environ.get("NOTERI_POOL_MAINTENANCE_APPROVED_SHA") == expected_sha,
         "new_sha_authorization_required")


def preflight(*, local: Path, expected_sha: str, live: bool = True) -> dict[str, Any]:
    need(socket.gethostname().casefold() == "noteri" and os.name == "nt"
         and bool(SHA40.fullmatch(expected_sha)), "host_or_sha_not_allowed")
    source = checked(Path(__file__).resolve().parents[1])
    head, origin, status = git_identity(source)
    need(head == expected_sha and origin in ALLOWED_ORIGIN and status == "",
         "checkout_not_exact_or_clean")
    profile = json.loads(checked(local / reference.PROFILE_RELATIVE).read_text(
        encoding="utf-8")).get("profile")
    need(profile == "NORMAL", "host_not_normal")
    paths = selected_paths(local)
    runner_source = checked(source / "scripts" / RUNNER).read_bytes()
    native_source = checked(source / "scripts" / "noteri_worker_pool_native_stage.py")
    installed = paths["runner"].read_bytes()
    need(paths["runner"].is_file() and paths["runner"].stat().st_nlink == 1
         and paths["stage_runner"].is_file()
         and sha(paths["stage_runner"].read_bytes()) == sha(native_source.read_bytes())
         and bool(installed) and len(installed) <= 32768,
         "runtime_source_scope")
    canonical = rules_pin.current_rules_sha()
    need(rules_pin.pinned_sha(runner_source.decode("utf-8")) == canonical
         and rules_pin.pinned_sha(installed.decode("utf-8")) == OLD_RULES_SHA
         and rules_pin.candidate_source(installed.decode("utf-8"), canonical)
            .encode("utf-8") == runner_source,
         "runner_not_single_sha_change")
    report = release_audit.audit(
        source=paths["source_pool"], release=paths["release"],
        hostname="Noteri", platform="nt", profile="NORMAL",
        inspect_git=stage.git_identity)
    need(report.get("source_identity_verified") is True
         and report.get("installed_manifest") == "valid"
         and report.get("result") == "RELEASE_MISMATCH"
         and report.get("expected_file_count") == 38
         and report.get("extra") == [cache.CACHE_LABEL]
         and all(report["counts"].get(x) == 0 for x in (
             "missing", "hash_mismatch", "unsafe", "manifest_keys_missing",
             "manifest_keys_extra", "manifest_hash_mismatch"))
         and report.get("manifest_metadata_mismatch") == [],
         "release_not_exact_cache_only")
    cache_path = checked(paths["release"] / cache.CACHE_RELATIVE)
    need(cache_path.is_file() and cache_path.stat().st_nlink == 1
         and cache_path.read_bytes()[:4] == importlib.util.MAGIC_NUMBER
         and stage.file_sha256(cache_path) == CACHE_SHA256,
         "cache_not_expected_hash")
    need(cache._backups(paths["quarantine"]) == [], "cache_backup_collision")
    xml = task_xml()
    user = f"{socket.gethostname()}\\{__import__('getpass').getuser()}"
    need(authenticated.xml_difference_fields(
             xml, paths["python"], paths["runner"], user) == []
         and activation.task_com_mismatches(
             paths["python"], paths["runner"], user,
             paths["runtime"] / "control" / control.TARGET_NAME) == []
         and activation.listener_owned_by_task(
             paths["python"], paths["runner"]) is True,
         "task_identity_unproved")
    idle = queue_safe(local)
    need(paths["database"].is_file()
         and 0 < paths["database"].stat().st_size <= MAX_DB,
         "database_unavailable")
    return {"source": source, "paths": paths, "old_runner": installed,
            "new_runner": runner_source, "xml": xml, "old_sha": sha(installed),
            "new_sha": sha(runner_source), "queue": idle,
            "code_sha": expected_sha}


def sqlite_consistent_backup(source: Path, target: Path) -> str:
    """SQLite Online Backup API includes committed WAL; never copy a live .db."""
    checked(source)
    checked(target)
    need(not target.exists() and not stage.is_link(target), "backup_collision")
    for suffix in ("-wal", "-shm"):
        checked(Path(str(source) + suffix))
    from urllib.parse import quote
    uri = "file:" + quote(source.as_posix(), safe="/:") + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=2)
    try:
        con.execute("PRAGMA query_only=ON")
        need(con.execute("PRAGMA query_only").fetchone()[0] == 1,
             "database_not_read_only")
        target_con = sqlite3.connect(target, timeout=2)
        try:
            con.backup(target_con, pages=64, sleep=0.01)
            target_con.commit()
            need(target_con.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
                 "sqlite_backup_integrity")
        finally:
            target_con.close()
    finally:
        con.close()
    need(0 < target.stat().st_size <= MAX_DB, "sqlite_backup_size")
    return stage.file_sha256(target)


def _write_once(file: Path, content: bytes) -> str:
    checked(file)
    with file.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    need(file.read_bytes() == content, "backup_readback_mismatch")
    return sha(content)


def _acl(path: Path) -> bytes:
    """Compare existing Windows owner/group/DACL; never grant rights."""
    try:
        import win32security  # type: ignore
        flags = (win32security.OWNER_SECURITY_INFORMATION
                 | win32security.GROUP_SECURITY_INFORMATION
                 | win32security.DACL_SECURITY_INFORMATION)
        return bytes(win32security.GetFileSecurity(str(path), flags)
                     .GetSecurityDescriptorBinaryForm())
    except Exception:
        raise MaintenanceBlocked("runner_acl_unavailable") from None


def _atomic_runner(target: Path, payload: bytes) -> None:
    checked(target)
    need(target.is_file() and target.stat().st_nlink == 1,
         "runner_file_invalid")
    previous_acl = _acl(target)
    temporary = target.with_name(target.name + ".maintenance-stage")
    need(not temporary.exists() and not stage.is_link(temporary),
         "runner_stage_collision")
    try:
        shutil.copy2(target, temporary)
        need(_acl(temporary) == previous_acl, "runner_acl_would_change")
        with temporary.open("wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        need(sha(temporary.read_bytes()) == sha(payload)
             and _acl(temporary) == previous_acl,
             "runner_candidate_unverified")
        os.replace(temporary, target)
        need(sha(target.read_bytes()) == sha(payload)
             and _acl(target) == previous_acl,
             "runner_postwrite_unverified")
    finally:
        if temporary.exists():
            temporary.unlink()  # own temporary only; never release or task.


def _zero_instances(local: Path) -> bool:
    return stopped_task_registered(local)


def _stop(local: Path) -> None:
    ended = activation.schtasks("/End", "/TN", activation.TASK_NAME)
    need(ended.returncode == 0, "task_stop_failed")
    for _ in range(24):
        if _zero_instances(local):
            return
        time.sleep(0.5)
    raise MaintenanceBlocked("task_stop_not_proved")


def _start(local: Path, paths: dict) -> None:
    need(_zero_instances(local), "task_not_stopped_for_start")
    started = activation.schtasks("/Run", "/TN", activation.TASK_NAME)
    need(started.returncode == 0, "task_start_failed")
    for _ in range(30):
        if activation.verify_api(paths["token"], paths["python"], paths["runner"]):
            return
        time.sleep(0.5)
    raise MaintenanceBlocked("api_auth_readback_failed")


def _task_xml_stable(initial: bytes) -> None:
    need(task_xml() == initial, "task_registration_changed")


def _quarantine(paths: dict) -> str:
    parent = checked(paths["quarantine"].parent)
    parent.mkdir(parents=True, exist_ok=True)
    checked(parent)
    source = checked(paths["release"] / cache.CACHE_RELATIVE)
    need(source.is_file() and stage.file_sha256(source) == CACHE_SHA256,
         "cache_changed")
    directory = paths["quarantine"]
    checked(directory)
    directory.mkdir(exist_ok=False)
    dest = checked(directory / f"{cache.CACHE_RELATIVE.name}.{CACHE_SHA256}.quarantined")
    need(not dest.exists(), "quarantine_backup_collision")
    os.replace(source, dest)
    try:
        need(stage.file_sha256(dest) == CACHE_SHA256,
             "quarantine_hash_drift")
        need(cache._backups(directory) == [(dest, CACHE_SHA256)],
             "quarantine_readback_failed")
        manifest = json.loads((paths["release"] / "manifest.json").read_text())
        need(stage.validate_staged(paths["release"], manifest),
             "release_still_untrusted")
    except Exception:
        # Restore only the exact known bytecode from our own destination.
        if (not source.exists() and dest.is_file()
                and stage.file_sha256(dest) == CACHE_SHA256):
            os.replace(dest, source)
        raise
    return CACHE_SHA256


def _backup_before_stop(plan: dict, base: Path) -> dict[str, str]:
    checked(base)
    need(not base.exists(), "maintenance_backup_collision")
    base.mkdir(parents=True, exist_ok=False)
    # No credentials, token or key are copied. Task XML is private, not logged.
    return {
        "runner": _write_once(base / "runner-before.py", plan["old_runner"]),
        "task_xml": _write_once(base / "task-before.xml", plan["xml"]),
    }


def _safe_rollback(local: Path, plan: dict, base: Path, *, stopped: bool) -> bool:
    """Recover old runner, keep pyc quarantined so immutable release can start.

    If state cannot be proven safe, do not overwrite/restore blindly. Preserve
    the backup and report failure for manual recovery under a new authorization.
    """
    try:
        paths = plan["paths"]
        if not stopped:
            return False
        # No second stop attempt here: an uncertain stop must be reconciled,
        # never retried merely to make the postcondition look successful.
        if not _zero_instances(local):
            return False
        original_cache = checked(paths["release"] / cache.CACHE_RELATIVE)
        if original_cache.exists():
            need(stage.file_sha256(original_cache) == CACHE_SHA256,
                 "rollback_cache_untrusted")
            _quarantine(paths)
        old = checked(base / "runner-before.py").read_bytes()
        need(sha(old) == plan["old_sha"], "rollback_backup_drift")
        if sha(paths["runner"].read_bytes()) != sha(old):
            _atomic_runner(paths["runner"], old)
        _task_xml_stable(plan["xml"])
        _start(local, paths)
        _task_xml_stable(plan["xml"])
        return True
    except Exception:
        return False


def apply(*, local: Path, expected_sha: str, confirm: str) -> dict[str, Any]:
    approval_required(expected_sha, confirm=confirm)
    plan = preflight(local=local, expected_sha=expected_sha)
    paths = plan["paths"]
    folder = paths["maintenance"] / expected_sha
    lock = paths["maintenance"] / ".maintenance-exclusive.lock"
    checked(paths["maintenance"])
    paths["maintenance"].mkdir(exist_ok=True)
    checked(lock)
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stopped = False
    started = False
    rollback_verified = False
    try:
        # Readback immediately before stopping. No queue claim or enrollment.
        queue_safe(local)
        need(activation.listener_owned_by_task(paths["python"], paths["runner"]),
             "listener_identity_drift")
        backups = _backup_before_stop(plan, folder)
        need(backups == {"runner": plan["old_sha"], "task_xml": sha(plan["xml"])},
             "backup_hash_mismatch")
        _task_xml_stable(plan["xml"])
        stopped = True  # Stop may partially succeed before returning.
        _stop(local)
        _task_xml_stable(plan["xml"])
        queue_safe(local)
        dbhash = sqlite_consistent_backup(paths["database"], folder / "pool-consistent.db")
        need(_zero_instances(local), "service_restarted_during_backup")
        queue_safe(local)
        _quarantine(paths)
        need(_zero_instances(local), "service_restarted_during_quarantine")
        _atomic_runner(paths["runner"], plan["new_runner"])
        need(_zero_instances(local), "service_restarted_during_runner_update")
        _task_xml_stable(plan["xml"])
        _start(local, paths)
        # Independent installed-source, task XML/COM, 401 control and authenticated
        # contract replay. A healthy GET /health alone is not acceptance.
        verified = authenticated.attest(
            local=local, host=socket.gethostname(), platform=os.name,
            user=__import__("getpass").getuser(),
        )
        need(verified.get("result") == "AUTHENTICATED_READBACK_OK"
             and verified.get("contract_replay_verified") is True
             and verified.get("negative_auth_verified") is True,
             "authenticated_installation_readback_failed")
        started = True
        need(stage.file_sha256(paths["runner"]) == plan["new_sha"],
             "runner_final_hash_wrong")
        _task_xml_stable(plan["xml"])
        need(cache._backups(paths["quarantine"])[0][1] == CACHE_SHA256,
             "cache_backup_not_verified")
        return {"result": "INPLACE_MAINTENANCE_VERIFIED", "changed": True,
                "source_sha": expected_sha, "runner_sha256": plan["new_sha"],
                "previous_runner_sha256": plan["old_sha"],
                "sqlite_backup_sha256": dbhash,
                "task_xml_sha256": sha(plan["xml"]),
                "cache_backup_sha256": CACHE_SHA256,
                "api_authenticated": True, "service_preserved": True}
    except Exception:
        rollback_verified = _safe_rollback(
            local, plan, folder, stopped=stopped,
        ) if stopped else False
        return {"result": "MAINTENANCE_ROLLED_BACK" if rollback_verified
                else ("MAINTENANCE_BLOCKED_RECONCILE" if stopped
                      else "MAINTENANCE_BLOCKED_NO_STOP"),
                "source_sha": expected_sha, "changed": stopped,
                "rollback_verified": rollback_verified,
                "backup_retained": folder.exists(),
                "service_preserved": rollback_verified or not stopped}
    finally:
        os.close(fd)
        # An ambiguous interrupted update holds its lease until reconciliation.
        if started or rollback_verified or not stopped:
            lock.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    result: dict[str, Any] = {"schema_version": SCHEMA, "result": "BLOCKED",
                              "state_changed": False, "task_deleted": False,
                              "secrets_changed": False, "worker_registered": False}
    try:
        local = Path(os.environ["LOCALAPPDATA"])
        if args.mode == "plan":
            proof = preflight(local=local, expected_sha=args.expected_head)
            result.update(result="INPLACE_MAINTENANCE_PLAN_READY",
                          installed_sha256=proof["old_sha"],
                          candidate_sha256=proof["new_sha"],
                          queue=proof["queue"], task_registered=True,
                          stop_required=True, backups_created=False)
        else:
            applied = apply(local=local, expected_sha=args.expected_head,
                            confirm=args.confirm)
            result.update(applied)
            result["state_changed"] = bool(applied.get("changed"))
    except (MaintenanceBlocked, OSError, ValueError, TypeError, KeyError,
            stage.StageBlocked, rules_pin.SyncBlocked, sqlite3.Error) as exc:
        result["result"] = str(exc) if isinstance(exc, MaintenanceBlocked) else "BLOCKED_PREFLIGHT"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] in (
        "INPLACE_MAINTENANCE_PLAN_READY", "INPLACE_MAINTENANCE_VERIFIED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
