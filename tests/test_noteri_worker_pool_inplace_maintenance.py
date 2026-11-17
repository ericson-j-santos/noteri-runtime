"""Noteri registered-task maintenance contracts: backup/rollback in isolated fixtures.

NO real Task Scheduler, token, service stop, Qwen, Worker Pool claim or deploy.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_inplace_maintenance as m

SHA = "a" * 40
XML = b"<Task>private-synthetic-owner</Task>"
OLD = b"RULES_SHA = '" + b"0" * 40 + b"'\n"
NEW = b"RULES_SHA = '" + b"f" * 40 + b"'\n"


def plan_fixture(tmp_path):
    work = tmp_path / "work"
    runtime = tmp_path / "ReqSys" / "NoteriWorkerPool"
    installed = runtime / "bin" / m.RUNNER
    installed.parent.mkdir(parents=True)
    installed.write_bytes(OLD)
    release = runtime / "releases" / "old"
    pycache = release / m.cache.CACHE_RELATIVE
    pycache.parent.mkdir(parents=True)
    pycache.write_bytes(importlib.util.MAGIC_NUMBER + b"cache-test")
    (release / "manifest.json").write_text('{"files":{}}')
    quarantine = runtime / "quarantine" / "old"
    quarantine.parent.mkdir(parents=True)
    maintenance = runtime / "maintenance"
    source = runtime / "data" / "pool.db"
    source.parent.mkdir(parents=True)
    db = sqlite3.connect(source)
    db.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO data VALUES (1, 'before')")
    db.commit()
    db.close()
    work.mkdir()
    selected = {
        "runtime": runtime, "release": release, "runner": installed,
        "database": source, "quarantine": quarantine, "maintenance": maintenance,
        "token": runtime / "credentials" / "api-token.txt",
        "python": runtime / "venvs" / "python.exe",
    }
    return {"paths": selected, "old_runner": OLD, "new_runner": NEW,
            "old_sha": m.sha(OLD), "new_sha": m.sha(NEW), "xml": XML,
            "code_sha": SHA}


def allow(monkeypatch):
    monkeypatch.setenv("NOTERI_POOL_MAINTENANCE_APPROVED_SHA", SHA)
    # Synthetic mutation tests use an explicit verified-fence fixture.
    # Production apply() always executes the real read-only sink verifier.
    monkeypatch.setattr(m, "require_fence", lambda: None)


def simulate(monkeypatch, tmp_path, *, failure=None):
    proof = plan_fixture(tmp_path)
    events = []
    stopped = [False]
    monkeypatch.setattr(m, "preflight", lambda **_: proof)
    monkeypatch.setattr(m, "queue_safe", lambda _: {"workers": 0})
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: True)
    monkeypatch.setattr(m, "_zero_instances", lambda _: stopped[0])
    monkeypatch.setattr(m, "_task_xml_stable", lambda xml:
                        events.append(("xml", m.sha(xml))))
    def stop(_):
        events.append(("stop",))
        stopped[0] = True
        if failure == "stop":
            raise m.MaintenanceBlocked("stop_failed_test")
    def start(_, paths):
        events.append(("start",))
        if failure == "start":
            raise m.MaintenanceBlocked("api_failed_test")
        stopped[0] = False
    monkeypatch.setattr(m, "_stop", stop)
    monkeypatch.setattr(m, "_start", start)
    monkeypatch.setattr(m, "_atomic_runner", lambda path, data:
                        (events.append(("replace", m.sha(data))),
                         path.write_bytes(data)))
    monkeypatch.setattr(m.authenticated, "attest", lambda **_:
                        {"result": "AUTHENTICATED_READBACK_OK",
                         "contract_replay_verified": True,
                         "negative_auth_verified": True}
                        if failure != "attestation"
                        else {"result": "BLOCKED_AUTH_CONTRACT",
                              "contract_replay_verified": False,
                              "negative_auth_verified": False})
    def quarantine(paths):
        events.append(("quarantine",))
        dest = paths["quarantine"]
        dest.mkdir()
        src = paths["release"] / m.cache.CACHE_RELATIVE
        src.rename(dest / (src.name + "." + m.CACHE_SHA256 + ".quarantined"))
        return m.CACHE_SHA256
    monkeypatch.setattr(m, "_quarantine", quarantine)
    monkeypatch.setattr(m.cache, "_backups", lambda folder: [(
        folder / ("secure_file.cpython-314.pyc." + m.CACHE_SHA256 + ".quarantined"),
        m.CACHE_SHA256,
    )])
    allow(monkeypatch)
    return proof, events


def test_missing_destination_fence_blocks_before_preflight(tmp_path, monkeypatch):
    monkeypatch.setenv("NOTERI_POOL_MAINTENANCE_APPROVED_SHA", SHA)
    monkeypatch.delenv("NOTERI_POOL_MAINTENANCE_FENCE_SEQUENCE", raising=False)
    called = []
    monkeypatch.setattr(m, "preflight", lambda **_:
                        called.append("unsafe") or {})
    with pytest.raises(m.MaintenanceBlocked, match="fence_sink_not_verified"):
        m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert called == []


def test_no_approval_never_reaches_preflight(tmp_path, monkeypatch):
    called = []
    monkeypatch.delenv("NOTERI_POOL_MAINTENANCE_APPROVED_SHA", raising=False)
    monkeypatch.setattr(m, "preflight", lambda **_:
                        called.append("bad") or (_ for _ in ()).throw(
                            AssertionError("not called")))
    with pytest.raises(m.MaintenanceBlocked, match="new_sha_authorization_required"):
        m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert called == []


@pytest.mark.parametrize("bad", ["", "authorize", "MAINTAIN-OTHER", "MAINTAIN-*"])
def test_wrong_confirmation_fails_closed(tmp_path, monkeypatch, bad):
    allow(monkeypatch)
    with pytest.raises(m.MaintenanceBlocked, match="new_sha_authorization_required"):
        m.apply(local=tmp_path, expected_sha=SHA, confirm=bad)


def test_real_sqlite_backup_includes_committed_wal_records(tmp_path):
    src, dest = tmp_path / "pool.db", tmp_path / "backup.db"
    writer = sqlite3.connect(src)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE activity (name TEXT)")
    writer.commit()
    writer.execute("INSERT INTO activity VALUES ('persisted-in-wal')")
    writer.commit()
    assert Path(str(src) + "-wal").is_file()
    signature = m.sqlite_consistent_backup(src, dest)
    with sqlite3.connect(dest) as read:
        assert read.execute("SELECT name FROM activity").fetchone() == (
            "persisted-in-wal",)
        assert read.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert signature == m.sha(dest.read_bytes())
    assert writer.execute("SELECT count(*) FROM activity").fetchone() == (1,)
    writer.close()


def test_sqlite_backup_refuses_existing_backup(tmp_path):
    src, dest = tmp_path / "pool.db", tmp_path / "backup.db"
    sqlite3.connect(src).close()
    dest.write_bytes(b"keep-this")
    with pytest.raises(m.MaintenanceBlocked, match="backup_collision"):
        m.sqlite_consistent_backup(src, dest)
    assert dest.read_bytes() == b"keep-this"


def test_exact_registration_stopped_means_com_zero_and_port_absent(
    tmp_path, monkeypatch,
):
    real_client = types.ModuleType("win32com.client")
    class Count:
        def __init__(self, count):
            self.Count = count
    class Task:
        def GetInstances(self, _):
            return Count(0)
    class Folder:
        def GetTask(self, name):
            assert name == "NoteriWorkerPoolApi"
            return Task()
    class Service:
        def Connect(self):
            pass
        def GetFolder(self, name):
            assert name == r"\Automation"
            return Folder()
    real_client.Dispatch = lambda name: Service()
    win32com = types.ModuleType("win32com")
    win32com.client = real_client
    monkeypatch.setitem(sys.modules, "win32com", win32com)
    monkeypatch.setitem(sys.modules, "win32com.client", real_client)
    monkeypatch.setattr(m.venv, "_paths", lambda p: (
        tmp_path, tmp_path / "release", tmp_path / "venv"))
    monkeypatch.setattr(m.control, "verify", lambda p: True)
    monkeypatch.setattr(m.site, "addsitedir", lambda p: None)
    monkeypatch.setattr(m.activation, "listener_absent", lambda: True)
    assert m.stopped_task_registered(tmp_path) is True
    monkeypatch.setattr(m.activation, "listener_absent", lambda: False)
    assert m.stopped_task_registered(tmp_path) is False


def test_task_status_unknown_cannot_attest_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(m.control, "verify", lambda p: False)
    monkeypatch.setattr(m.venv, "_paths", lambda p: (
        tmp_path, tmp_path, tmp_path))
    assert m.stopped_task_registered(tmp_path) is False


def test_transaction_commits_only_after_backup_stop_quarantine_and_readback(
    tmp_path, monkeypatch,
):
    proof, events = simulate(monkeypatch, tmp_path)
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] == "INPLACE_MAINTENANCE_VERIFIED"
    assert result["api_authenticated"] is True
    assert proof["paths"]["runner"].read_bytes() == NEW
    assert events.index(("stop",)) < events.index(("quarantine",))
    assert events.index(("quarantine",)) < events.index(("replace", m.sha(NEW)))
    assert events.index(("replace", m.sha(NEW))) < events.index(("start",))
    backups = proof["paths"]["maintenance"] / SHA
    assert (backups / "runner-before.py").read_bytes() == OLD
    assert (backups / "task-before.xml").read_bytes() == XML
    assert (backups / "pool-consistent.db").is_file()
    assert result["sqlite_backup_sha256"] == m.sha(
        (backups / "pool-consistent.db").read_bytes())
    assert not (proof["paths"]["maintenance"] /
                ".maintenance-exclusive.lock").exists()


def test_fail_before_stop_preserves_runner_and_does_not_claim_success(
    tmp_path, monkeypatch,
):
    proof, events = simulate(monkeypatch, tmp_path)
    monkeypatch.setattr(m, "_backup_before_stop", lambda *_:
                        (_ for _ in ()).throw(m.MaintenanceBlocked("backup_failed")))
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] != "INPLACE_MAINTENANCE_VERIFIED"
    assert proof["paths"]["runner"].read_bytes() == OLD
    assert ("stop",) not in events


def test_failed_restart_requires_rollback_before_completion(tmp_path, monkeypatch):
    proof, events = simulate(monkeypatch, tmp_path, failure="start")
    called = []
    monkeypatch.setattr(m, "_safe_rollback", lambda *a, **k:
                        called.append(k) or False)
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] == "MAINTENANCE_BLOCKED_RECONCILE"
    assert result["rollback_verified"] is False
    assert called
    assert proof["paths"]["runner"].read_bytes() == NEW
    # An ambiguous state must preserve the backup/maintenance lock for review.
    assert (proof["paths"]["maintenance"] / SHA / "runner-before.py").exists()


def test_quarantine_refuses_unsafe_release(tmp_path, monkeypatch):
    proof = plan_fixture(tmp_path)
    paths = proof["paths"]
    monkeypatch.setattr(m.stage, "validate_staged", lambda *_: False)
    monkeypatch.setattr(m.stage, "file_sha256", lambda p:
                        m.CACHE_SHA256 if p.name.endswith(".pyc")
                        or p.name.endswith(".quarantined") else m.sha(p.read_bytes()))
    with pytest.raises(m.MaintenanceBlocked):
        # Source in fixture lacks the known digest; source is never moved.
        m._quarantine(paths)
    assert (paths["release"] / m.cache.CACHE_RELATIVE).is_file()


def test_real_runner_atomic_replace_rejects_acl_change_before_replace(
    tmp_path, monkeypatch,
):
    runner = tmp_path / "runner.py"
    runner.write_bytes(OLD)
    def acl(path):
        return b"first" if path == runner else b"changed"
    monkeypatch.setattr(m, "_acl", acl)
    with pytest.raises(m.MaintenanceBlocked, match="runner_acl_would_change"):
        m._atomic_runner(runner, NEW)
    assert runner.read_bytes() == OLD
    assert not runner.with_name(runner.name + ".maintenance-stage").exists()


def test_runner_replace_success_preserves_identical_acl(tmp_path, monkeypatch):
    runner = tmp_path / "runner.py"
    runner.write_bytes(OLD)
    monkeypatch.setattr(m, "_acl", lambda path: b"same-acl")
    m._atomic_runner(runner, NEW)
    assert runner.read_bytes() == NEW
    assert not runner.with_name(runner.name + ".maintenance-stage").exists()


def test_backup_before_stop_never_overwrites_existing_evidence(tmp_path):
    proof = plan_fixture(tmp_path)
    folder = proof["paths"]["maintenance"] / SHA
    folder.mkdir(parents=True)
    (folder / "runner-before.py").write_bytes(b"original")
    with pytest.raises(m.MaintenanceBlocked, match="maintenance_backup_collision"):
        m._backup_before_stop(proof, folder)
    assert (folder / "runner-before.py").read_bytes() == b"original"


def test_no_task_deletion_or_privilege_change_in_source():
    data = Path(m.__file__).read_text(encoding="utf-8")
    assert '"/Delete"' not in data
    assert "/Create" not in data
    assert "runas" not in data.lower()
    assert "ShellExecute" not in data
    assert "register_worker" not in data
    assert "claim_exact" not in data
    assert "UPDATE tasks" not in data
    assert "DELETE FROM" not in data
    assert "sqlite3.connect" in data
    assert ".backup(" in data
    assert "/End" in data and "/Run" in data



def test_an_unauthenticated_health_readback_blocks_success_and_rolls_back(
    tmp_path, monkeypatch,
):
    proof, events = simulate(monkeypatch, tmp_path, failure="attestation")
    called = []
    monkeypatch.setattr(m, "_safe_rollback", lambda *a, **kw:
                        called.append(kw) or True)
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] == "MAINTENANCE_ROLLED_BACK"
    assert result["rollback_verified"] is True
    assert result["api_authenticated"] if "api_authenticated" in result else True
    assert ("start",) in events
    assert called


def test_unverifiable_rules_lookup_uses_no_backup_or_stop(tmp_path, monkeypatch):
    allow(monkeypatch)
    def bad_preflight(**_):
        raise m.rules_pin.SyncBlocked("BLOCKED_CANONICAL_UNAVAILABLE")
    monkeypatch.setattr(m, "preflight", bad_preflight)
    with pytest.raises(m.rules_pin.SyncBlocked):
        m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert not (tmp_path / "ReqSys").exists()



def test_registered_identity_accepts_only_com_attested_omitted_defaults(
    tmp_path, monkeypatch,
):
    proof = plan_fixture(tmp_path)
    paths = proof["paths"]
    monkeypatch.setattr(m.control, "verify", lambda _: True)
    monkeypatch.setattr(m.activation, "task_com_mismatches", lambda *_: [])
    monkeypatch.setattr(m.activation, "task_matches", lambda *_: False)
    monkeypatch.setattr(m.authenticated, "xml_difference_fields", lambda *_:
                        ["run_level", "boot_trigger"])
    monkeypatch.setattr(m.authenticated, "xml_optional_field_states", lambda *_:
                        {"run_level": "missing", "boot_trigger": "missing"})
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: True)
    m.verify_registered_identity(XML, paths)  # Registered but XML omits defaults.


@pytest.mark.parametrize("fields,states,code", [
    (["run_level"], {"run_level": "different"}, "task_xml_identity_unproved"),
    (["action_path"], {"action_path": "missing"}, "task_xml_identity_unproved"),
    ([], {}, "task_xml_identity_unproved"),
])
def test_registered_identity_refuses_unauthorized_xml_drift(
    tmp_path, monkeypatch, fields, states, code,
):
    proof = plan_fixture(tmp_path)
    paths = proof["paths"]
    monkeypatch.setattr(m.control, "verify", lambda _: True)
    monkeypatch.setattr(m.activation, "task_com_mismatches", lambda *_: [])
    monkeypatch.setattr(m.activation, "task_matches", lambda *_: False)
    monkeypatch.setattr(m.authenticated, "xml_difference_fields", lambda *_: fields)
    monkeypatch.setattr(m.authenticated, "xml_optional_field_states", lambda *_: states)
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: True)
    with pytest.raises(m.MaintenanceBlocked, match=code):
        m.verify_registered_identity(XML, paths)


def test_registered_identity_blocks_changed_com_or_unverified_listener(
    tmp_path, monkeypatch,
):
    paths = plan_fixture(tmp_path)["paths"]
    monkeypatch.setattr(m.control, "verify", lambda _: True)
    monkeypatch.setattr(m.activation, "task_matches", lambda *_: True)
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: True)
    monkeypatch.setattr(m.activation, "task_com_mismatches", lambda *_:
                        ["principal"])
    with pytest.raises(m.MaintenanceBlocked, match="task_com_identity_unproved"):
        m.verify_registered_identity(XML, paths)
    monkeypatch.setattr(m.activation, "task_com_mismatches", lambda *_: [])
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: False)
    with pytest.raises(m.MaintenanceBlocked, match="task_listener_identity_unproved"):
        m.verify_registered_identity(XML, paths)



def test_post_restart_attestation_failure_restarts_exact_original(
    tmp_path, monkeypatch,
):
    """Proven candidate may be re-stopped ONLY to restore prior runner."""
    proof, events = simulate(monkeypatch, tmp_path, failure="attestation")
    monkeypatch.setattr(m.activation, "verify_api", lambda *_: True)
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] == "MAINTENANCE_ROLLED_BACK"
    assert result["rollback_verified"] is True
    assert proof["paths"]["runner"].read_bytes() == OLD
    assert events.count(("stop",)) == 2
    assert events.count(("start",)) == 2
    assert events.index(("replace", m.sha(NEW))) < events.index(("replace", m.sha(OLD)))
    assert (proof["paths"]["maintenance"] / SHA / "runner-before.py").read_bytes() == OLD
    assert not (proof["paths"]["maintenance"] /
                ".maintenance-exclusive.lock").exists()


def test_failed_initial_stop_does_not_retry_if_original_still_healthy(
    tmp_path, monkeypatch,
):
    """No second Stop of the old service on an unsuccessful initial stop."""
    proof, events = simulate(monkeypatch, tmp_path)
    def unable_to_stop(_):
        events.append(("stop_failed",))
        raise m.MaintenanceBlocked("task_stop_failed")
    monkeypatch.setattr(m, "_stop", unable_to_stop)
    monkeypatch.setattr(m, "_zero_instances", lambda _: False)
    monkeypatch.setattr(m.activation, "verify_api", lambda *_: True)
    result = m.apply(local=tmp_path, expected_sha=SHA, confirm=m.CONFIRM)
    assert result["result"] == "MAINTENANCE_ROLLED_BACK"
    assert result["rollback_verified"] is True
    assert proof["paths"]["runner"].read_bytes() == OLD
    assert events.count(("stop_failed",)) == 1
    assert ("quarantine",) not in events
    assert ("start",) not in events


def test_unknown_runner_hash_never_stops_or_overwrites_during_rollback(
    tmp_path, monkeypatch,
):
    proof = plan_fixture(tmp_path)
    base = proof["paths"]["maintenance"] / SHA
    base.mkdir(parents=True)
    (base / "runner-before.py").write_bytes(OLD)
    proof["paths"]["runner"].write_bytes(b"tampered-runner")
    monkeypatch.setattr(m, "_zero_instances", lambda _: False)
    stop_calls = []
    monkeypatch.setattr(m, "_stop", lambda *_: stop_calls.append("stopped"))
    assert m._safe_rollback(tmp_path, proof, base, stopped=True) is False
    assert proof["paths"]["runner"].read_bytes() == b"tampered-runner"
    assert stop_calls == []


def test_unattributed_candidate_never_restarted_or_terminated_on_rollback(
    tmp_path, monkeypatch,
):
    proof = plan_fixture(tmp_path)
    base = proof["paths"]["maintenance"] / SHA
    base.mkdir(parents=True)
    (base / "runner-before.py").write_bytes(OLD)
    proof["paths"]["runner"].write_bytes(NEW)
    monkeypatch.setattr(m, "_zero_instances", lambda _: False)
    monkeypatch.setattr(m, "_task_xml_stable", lambda _: None)
    monkeypatch.setattr(m.activation, "listener_owned_by_task", lambda *_: False)
    stop_calls = []
    monkeypatch.setattr(m, "_stop", lambda *_: stop_calls.append("stopped"))
    assert m._safe_rollback(tmp_path, proof, base, stopped=True) is False
    assert proof["paths"]["runner"].read_bytes() == NEW
    assert stop_calls == []
