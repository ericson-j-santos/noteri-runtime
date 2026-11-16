"""Read-only Noteri Worker Pool queue audit; no recovery/claims/token output."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_queue_readonly as probe

NOW = datetime(2026, 11, 15, 23, 0, tzinfo=timezone.utc)


def fixture_db(tmp_path: Path) -> Path:
    path = tmp_path / "pool.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE tasks(state TEXT NOT NULL, leased_by TEXT,
                               lease_expires_at TEXT);
            CREATE TABLE task_attempts(ended_at TEXT);
            CREATE TABLE task_checkpoints(effect_state TEXT NOT NULL);
            CREATE TABLE workers(last_heartbeat_at TEXT NOT NULL);
        """)
    return path


def _stamp(when: datetime) -> str:
    return when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_empty_queue_is_observed_without_mutation_or_maintenance_approval(tmp_path):
    db = fixture_db(tmp_path)
    before = _hash(db)
    result = probe.inspect_database(db, now=NOW)
    assert result["result"] == "READ_ONLY_QUEUE_AUDIT_OK"
    assert result["queue_counts"] == {s: 0 for s in probe.STATES}
    assert result["leases_unexpired"] == 0
    assert result["open_attempt_records"] == 0
    assert result["workload_present"] is False
    assert result["maintenance_authorized"] is False
    assert result["query_only"] is True
    assert result["queue_mutation"] is False
    assert result["secrets_disclosed"] is False
    assert before == _hash(db)
    assert not (tmp_path / "pool.db-wal").exists()
    assert not (tmp_path / "pool.db-shm").exists()


def test_active_leases_and_stale_attempts_are_distinguished(tmp_path):
    db = fixture_db(tmp_path)
    fresh = _stamp(NOW + timedelta(seconds=100))
    expired = _stamp(NOW - timedelta(seconds=100))
    with sqlite3.connect(db) as con:
        con.executemany("INSERT INTO tasks VALUES (?, ?, ?)", [
            ("queued", None, None),
            ("leased", "builder-a", fresh),
            ("running", "builder-b", expired),
            ("validating", "validator-c", None),
            ("completed", None, None),
            ("blocked", None, None),
        ])
        con.executemany("INSERT INTO task_attempts VALUES (?)",
                        [(None,), (expired,)])
        con.executemany("INSERT INTO task_checkpoints VALUES (?)",
                        [("pending",), ("unknown",), ("confirmed",)])
        con.executemany("INSERT INTO workers VALUES (?)", [
            (_stamp(NOW - timedelta(seconds=30)),),
            (_stamp(NOW - timedelta(seconds=500)),),
        ])
    before = _hash(db)
    result = probe.inspect_database(db, now=NOW)
    assert result["result"] == "READ_ONLY_QUEUE_AUDIT_OK"
    assert result["queue_counts"]["queued"] == 1
    assert result["tasks_active_states"] == 3
    assert result["leases_unexpired"] == 1
    assert result["active_states_expired_or_missing_lease"] == 2
    assert result["open_attempt_records"] == 1
    assert result["unresolved_checkpoint_effects"] == 2
    assert result["registered_workers"] == 2
    assert result["workers_heartbeat_within_90s"] == 1
    assert result["workload_present"] is True
    assert before == _hash(db)


def test_file_not_found_or_untrusted_schema_fails_closed(tmp_path):
    missing = tmp_path / "pool.db"
    assert probe.inspect_database(missing, now=NOW)["result"] == "BLOCKED_DB_REFERENCE"
    missing.write_bytes(b"wrong schema")
    result = probe.inspect_database(missing, now=NOW)
    assert result["result"] == "BLOCKED_READ_ONLY_QUERY"
    missing.unlink()
    db = fixture_db(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE task_checkpoints")
    assert probe.inspect_database(db, now=NOW)["result"] == "BLOCKED_SCHEMA"


def test_unrecognized_state_does_not_return_false_no_work(tmp_path):
    db = fixture_db(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO tasks VALUES ('private_state', NULL, NULL)")
    result = probe.inspect_database(db, now=NOW)
    assert result["result"] == "BLOCKED_UNKNOWN_STATE"
    assert result["maintenance_authorized"] is False


def test_wal_without_shm_is_blocked_before_sqlite_connect(tmp_path):
    db = fixture_db(tmp_path)
    wal = tmp_path / "pool.db-wal"
    wal.write_bytes(b"synthetic-wal-sidecar")
    result = probe.inspect_database(db, now=NOW)
    assert result["result"] == "BLOCKED_SQLITE_WAL_UNAVAILABLE"
    assert result["queue_mutation"] is False
    assert not (tmp_path / "pool.db-shm").exists()


def test_symlinked_database_reference_is_never_followed(tmp_path):
    db = fixture_db(tmp_path)
    link = tmp_path / "pool-link.db"
    try:
        link.symlink_to(db)
    except (OSError, NotImplementedError):
        pytest.skip("Host cannot create symlinks")
    result = probe.inspect_database(link, now=NOW)
    assert result["result"] == "BLOCKED_READ_ONLY_QUERY"


def test_script_never_calls_mutating_snapshot_or_accepts_arbitrary_db_path():
    src = (Path(__file__).resolve().parents[1] /
           "scripts" / "noteri_worker_pool_queue_readonly.py").read_text(encoding="utf-8")
    assert "/v1/snapshot" in src  # explicitly documented as side-effecting
    assert "recover_expired_leases(" not in src
    assert "recover_stalled_tasks(" not in src
    assert "argparse" not in src
    assert "sys.argv" not in src
    assert "mode=ro" in src
    assert "PRAGMA query_only=ON" in src
    assert "pool.db" in src
    assert "subprocess." not in src
    assert "shutil." not in src
    assert ".write_text(" not in src
    assert ".unlink(" not in src
