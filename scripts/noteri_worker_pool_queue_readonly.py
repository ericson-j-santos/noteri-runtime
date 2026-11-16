#!/usr/bin/env python3
"""Report live Noteri Worker Pool task/lease counts without queue recovery.

Unlike GET /v1/snapshot in the pinned Worker Pool, this script NEVER calls
recover_expired_leases/recover_stalled_tasks. It opens the *installed* SQLite
database in mode=ro with PRAGMA query_only=ON, reads only aggregate counts and
never returns task IDs, token values or absolute host paths.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from scripts import noteri_worker_pool_authenticated_readback as authenticated
from scripts import noteri_worker_pool_native_stage as stage

STATES = ("queued", "leased", "running", "validating", "blocked", "completed", "failed")
ACTIVE = ("leased", "running", "validating")
SCHEMA = {
    "tasks": {"task_id", "repository", "issue_number", "state", "leased_by",
              "lease_expires_at", "fencing_required", "lease_generation"},
    "task_attempts": {"ended_at"},
    "task_checkpoints": {"effect_state"},
    "workers": {"last_heartbeat_at"},
    "pool_control": {"control_key", "enabled"},
}
MAX_DB_BYTES = 1_073_741_824
BASE = {"schema_version": "1", "source_sha": authenticated.SOURCE_SHA,
        "result": "BLOCKED", "database_mode": "read_only",
        "query_only": False, "queue_mutation": False,
        "secrets_disclosed": False, "service_changed": False,
        "execution_authorized": False, "maintenance_authorized": False}


def inspect_database(db_path: Path, *, now: datetime) -> dict:
    """Function parameter is testable; the CLI only uses the pinned local path."""
    result = dict(BASE)
    con = None
    try:
        if now.tzinfo is None:
            return {**result, "result": "BLOCKED_CLOCK"}
        stage.ensure_no_link_components(db_path)
        if not db_path.is_file() or not 0 < db_path.stat().st_size <= MAX_DB_BYTES:
            return {**result, "result": "BLOCKED_DB_REFERENCE"}
        # In WAL mode, connecting without a sidecar can create shared-memory
        # state. Fail closed rather than construct it during an inspection.
        wal = Path(str(db_path) + "-wal")
        shm = Path(str(db_path) + "-shm")
        for sidecar in (wal, shm):
            stage.ensure_no_link_components(sidecar)
        if wal.exists() and not shm.is_file():
            return {**result, "result": "BLOCKED_SQLITE_WAL_UNAVAILABLE"}
        uri = "file:" + quote(db_path.as_posix(), safe="/:") + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA query_only=ON")
        if con.execute("PRAGMA query_only").fetchone()[0] != 1:
            return {**result, "result": "BLOCKED_SQLITE_NOT_READONLY"}
        result["query_only"] = True
        con.execute("BEGIN")
        for table, required in SCHEMA.items():
            observed = {r["name"] for r in con.execute(
                "PRAGMA table_info(" + table + ")")}
            if not required.issubset(observed):
                return {**result, "result": "BLOCKED_SCHEMA"}
        counts = {s: 0 for s in STATES}
        for row in con.execute("SELECT state, COUNT(*) n FROM tasks GROUP BY state"):
            if row["state"] not in counts:
                return {**result, "result": "BLOCKED_UNKNOWN_STATE"}
            counts[row["state"]] = int(row["n"])
        stamp = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        recent = (now - timedelta(seconds=90)).astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z")
        active = con.execute(
            "SELECT COUNT(*) n FROM tasks WHERE state IN ('leased','running','validating') "
            "AND leased_by IS NOT NULL AND lease_expires_at > ?", (stamp,)).fetchone()["n"]
        expired = con.execute(
            "SELECT COUNT(*) n FROM tasks WHERE state IN ('leased','running','validating') "
            "AND (lease_expires_at IS NULL OR lease_expires_at <= ?)", (stamp,)).fetchone()["n"]
        open_attempts = con.execute(
            "SELECT COUNT(*) n FROM task_attempts WHERE ended_at IS NULL").fetchone()["n"]
        unresolved = con.execute(
            "SELECT COUNT(*) n FROM task_checkpoints WHERE effect_state IN "
            "('pending','unknown')").fetchone()["n"]
        registered = con.execute("SELECT COUNT(*) n FROM workers").fetchone()["n"]
        fresh = con.execute(
            "SELECT COUNT(*) n FROM workers WHERE last_heartbeat_at > ?",
            (recent,)).fetchone()["n"]
        # Only allowlisted, non-sensitive queue identity fields are returned.
        # Never export request_id, idempotency_key, lease_token, correlation_id,
        # private worktree paths or arbitrary task content.
        import re
        queue_sample = []
        for row in con.execute(
            "SELECT task_id,repository,issue_number,fencing_required,lease_generation "
            "FROM tasks WHERE state='queued' ORDER BY rowid LIMIT 5"
        ):
            task_id = str(row["task_id"])
            repo = str(row["repository"])
            if (not re.fullmatch(r"cwp-[a-f0-9]{24}", task_id) or
                    not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)):
                return {**result, "result": "BLOCKED_QUEUE_IDENTITY"}
            queue_sample.append({
                "task_id": task_id, "repository": repo,
                "issue_number": int(row["issue_number"]),
                "fencing_required": bool(row["fencing_required"]),
                "lease_generation": int(row["lease_generation"]),
            })
        cutover_row = con.execute(
            "SELECT enabled FROM pool_control WHERE control_key='fenced_cutover'"
        ).fetchone()
        if cutover_row is None or cutover_row["enabled"] not in (0, 1):
            return {**result, "result": "BLOCKED_CUTOVER_STATE"}
        cutover = bool(cutover_row["enabled"])
        con.execute("ROLLBACK")
        result.update(
            result="READ_ONLY_QUEUE_AUDIT_OK",
            observed_utc=stamp,
            queue_counts=counts,
            queued_task_sample=queue_sample,
            queued_task_sample_truncated=counts["queued"] > len(queue_sample),
            fenced_cutover_enabled=cutover,
            tasks_total=sum(counts.values()),
            tasks_active_states=sum(counts[s] for s in ACTIVE),
            leases_unexpired=int(active),
            active_states_expired_or_missing_lease=int(expired),
            open_attempt_records=int(open_attempts),
            unresolved_checkpoint_effects=int(unresolved),
            registered_workers=int(registered),
            workers_heartbeat_within_90s=int(fresh),
            workload_present=bool(sum(counts[s] for s in ACTIVE) or counts["queued"]
                                  or open_attempts or unresolved),
            # A live service has not been drained or admission-fenced; even
            # zero current tasks cannot authorize a maintenance window.
            maintenance_authorized=False,
        )
        return result
    except (OSError, ValueError, sqlite3.Error, stage.StageBlocked):
        return {**result, "result": "BLOCKED_READ_ONLY_QUERY"}
    finally:
        if con is not None:
            con.close()


def main() -> int:
    local_text = os.environ.get("LOCALAPPDATA", "")
    if not local_text:
        result = {**BASE, "result": "BLOCKED_LOCALAPPDATA"}
    else:
        local = Path(local_text)
        attestation = authenticated.attest(
            local=local, host=socket.gethostname(), platform=os.name,
            user=__import__("getpass").getuser(),
        )
        if attestation.get("result") != "AUTHENTICATED_READBACK_OK":
            result = {**BASE, "result": "BLOCKED_SERVICE_ATTESTATION",
                      "service_attestation_result": attestation.get("result", "BLOCKED")}
        else:
            db_path = (local / "ReqSys" / "NoteriWorkerPool" / "data" / "pool.db")
            result = inspect_database(db_path, now=datetime.now(timezone.utc))
            result["service_authenticated"] = True
            result["service_attestation_result"] = "AUTHENTICATED_READBACK_OK"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "READ_ONLY_QUEUE_AUDIT_OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
