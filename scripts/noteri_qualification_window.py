"""Bounded Noteri qualification window; never a generic command executor.

The existing profile writer and native collector are reused. A durable journal
records ownership before opening NORMAL. Finally restores ESTUDO. A killed
process is not claimed to be self-healing: a pending journal blocks reopening
and the next invocation performs restoration only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import socket
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

CONFIRM = "QUALIFY-NOTERI-AND-RESTORE-ESTUDO"
HOST = "Noteri"


class Blocked(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def host_lock(path: Path):
    """One window process per host. Other profile writers still need CAS checks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), "lock_symlink")
    if path.exists():
        require(not getattr(path.lstat(), "st_file_attributes", 0) & 0x400,
                "lock_reparse")
    handle = path.open("a+b")
    acquired = False
    try:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        acquired = True
        yield
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def run_window(*, source_sha: str, correlation_id: str, confirmation: str,
               read_profile: Callable, set_profile: Callable,
               collect: Callable, negative_control: Callable,
               read_journal: Callable, write_journal: Callable) -> dict:
    """Callbacks exist for unit tests; CLI binds only the fixed local adapters."""
    require(confirmation == CONFIRM, "confirmation_required")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_sha)), "source_sha_invalid")
    require(bool(re.fullmatch(r"[A-Za-z0-9_.:-]{8,120}", correlation_id)), "correlation_invalid")
    before = read_profile()
    require(str(before.get("host", "")).casefold() == HOST.casefold(), "profile_host")
    require(before.get("profile") in ("NORMAL", "ESTUDO"), "profile_invalid")
    journal = read_journal()
    if journal:
        require(isinstance(journal, dict) and journal.get("host") == HOST,
                "journal_invalid")
        require(journal.get("state") in ("restore_pending", "closed", "restored_after_interruption"),
                "journal_state_invalid")
        if journal.get("state") == "restore_pending":
            owner = journal.get("correlation_id")
            require(isinstance(owner, str) and 8 <= len(owner) <= 128, "journal_owner")
            if before["profile"] == "NORMAL":
                require(before.get("correlation_id") == owner, "recovery_owner_conflict")
                set_profile("ESTUDO", owner + ".restore")
            final = read_profile()
            require(final["profile"] == "ESTUDO" and final.get("accepts_new_development") is False,
                    "recovery_not_verified")
            result = {**journal, "state": "restored_after_interruption",
                      "restored_at": stamp(), "final_profile": "ESTUDO",
                      "restoration_verified": True, "qualified": False,
                      "hml_verified": False}
            write_journal(result)
            return result  # Recovery never opens a fresh window in the same call.
        if journal.get("correlation_id") == correlation_id:
            require(journal.get("source_sha") == source_sha, "replay_sha_conflict")
            require(before["profile"] == "ESTUDO" and before.get("accepts_new_development") is False,
                    "replay_profile_conflict")
            return {**journal, "replayed": True, "window_opened_by_this_call": False}
    require(before["profile"] == "ESTUDO" and before.get("accepts_new_development") is False,
            "initial_profile_not_estudo")
    result = {"schema_version": "1", "host": HOST, "source_sha": source_sha,
              "correlation_id": correlation_id, "state": "restore_pending",
              "prepared_at": stamp(), "initial_profile": "ESTUDO", "qualified": False,
              "hml_verified": False, "actions_qualified": False,
              "scope": "native_inventory", "window_opened_by_this_call": False,
              "production_touched": False, "secrets_read": False}
    write_journal(result)  # Fail before mutation if the durable intent cannot be saved.
    try:
        set_profile("NORMAL", correlation_id)
        active = read_profile()
        require(active["profile"] == "NORMAL" and active.get("correlation_id") == correlation_id
                and active.get("accepts_new_development") is True, "normal_readback_failed")
        result.update(window_opened_by_this_call=True, opened_at=stamp())
        write_journal(result)
        first, second = collect(), collect()
        for observed in (first, second):
            require(observed.get("host") == HOST and observed.get("source_sha") == source_sha
                    and observed.get("correlation_id") == correlation_id
                    and observed.get("status") == "observed"
                    and observed.get("hml_verified") is False
                    and observed.get("production_touched") is False
                    and observed.get("secrets_read") is False, "observation_binding")
            require(observed.get("rollback", {}).get("state_verified") is not False,
                    "runtime_state_unreconciled")
            require(observed.get("operating_profile") ==
                    {"profile": "NORMAL", "source": "file", "verified": True},
                    "normal_observation_unverified")
        comparable = lambda value: {k: v for k, v in value.items() if k != "generated_at"}
        require(comparable(first) == comparable(second), "independent_readback_changed")
        require(negative_control() is True, "negative_control_failed")
        result.update(qualified=True, observation=second,
                      negative_control_verified=True, independent_readback_verified=True,
                      observation_sha256=hashlib.sha256(
                          json.dumps(second, sort_keys=True).encode()).hexdigest())
    except Exception as exc:
        result.update(qualified=False, code=str(exc) if isinstance(exc, Blocked)
                      else type(exc).__name__)
    finally:
        try:
            active = read_profile()
            require(str(active.get("host", "")).casefold() == HOST.casefold(), "restore_host")
            if active.get("profile") == "NORMAL":
                require(active.get("correlation_id") == correlation_id, "restore_owner_conflict")
                set_profile("ESTUDO", correlation_id + ".restore")
            final = read_profile()
            require(final.get("profile") == "ESTUDO"
                    and final.get("accepts_new_development") is False
                    and str(final.get("host", "")).casefold() == HOST.casefold(),
                    "restore_readback_failed")
            result.update(state="closed", final_profile="ESTUDO",
                          restoration_verified=True, closed_at=stamp())
        except Exception as exc:
            result.update(state="restore_pending", qualified=False,
                          restoration_verified=False,
                          restoration_code=str(exc) if isinstance(exc, Blocked)
                          else type(exc).__name__)
        write_journal(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    try:
        require(args.confirm == CONFIRM, "confirmation_required")
        require(os.name == "nt" and socket.gethostname().casefold() == HOST.casefold(),
                "noteri_windows_required")
        import noteri_native_qualification as native
        import noteri_host_profile_agent as profile
        import noteri_qualification_receipt as receipt
        native.source_head(args.source_sha)
        target = profile.default_profile_path()
        # Profile path/parents are checked by native.read_regular before any mutation.
        native.read_json(target)
        journal_path = target.with_name("qualification-window.json")
        lock_path = target.with_name("qualification-window.lock")

        def negative() -> bool:
            try:
                native.source_head("0" * 40)
            except native.Blocked as exc:
                return str(exc) == "source_sha_mismatch"
            return False

        def set_value(value: str, correlation: str):
            # Reuse the existing writer, host validation and independent readback.
            return profile.set_profile(target, expected_host=HOST,
                                       profile=value, correlation_id=correlation)

        def observe():
            # Read-only existing probes; never registers/starts a runner or reads credentials.
            import noteri_control_plane_probe as control
            observation = native.collect(args.source_sha, args.correlation_id)
            observation["runner_probe"] = {
                "listener_detected": control.runner_listener_detected(),
                "headless_task": control.task_status(),
                "actions_registry_checked": False,
                "actions_scope_verified": False,
            }
            return observation

        with host_lock(lock_path):
            result = run_window(
                source_sha=args.source_sha, correlation_id=args.correlation_id,
                confirmation=args.confirm, read_profile=lambda: native.read_json(target),
                set_profile=set_value,
                collect=observe,
                negative_control=negative,
                read_journal=lambda: native.read_json(journal_path) if journal_path.exists() else None,
                write_journal=lambda value: receipt.write_atomic(journal_path, value))
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0 if result.get("qualified") and result.get("restoration_verified") else 2
    except Exception as exc:
        print(json.dumps({"qualified": False, "hml_verified": False,
                          "code": str(exc) if isinstance(exc, Blocked) else type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
