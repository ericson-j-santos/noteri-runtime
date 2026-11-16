"""Bounded, reversible, source-pinned cache quarantine unit tests (no real host)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_cache_quarantine as q

ORIGIN = "https://github.com/ericson-j-santos/engineering-worker-pool"


def fixture(tmp_path):
    source = tmp_path / "_worker_pool"
    for folder in ("app", "contracts/v1"):
        (source / folder).mkdir(parents=True)
    (source / "app/__init__.py").write_text("", encoding="utf-8")
    (source / "app/main.py").write_text("def run(): return 1\n", encoding="utf-8")
    (source / "contracts/v1/contract.json").write_text("{}", encoding="utf-8")
    (source / "requirements.txt").write_text("fastapi==1.0\n", encoding="utf-8")
    releases = tmp_path / "NoteriWorkerPool" / "releases"
    manifest = stage.stage(source=source, releases=releases,
                           expected_sha=q.SOURCE_SHA, hostname="Noteri",
                           profile="NORMAL", platform="nt",
                           inspect_git=lambda _: (q.SOURCE_SHA, ORIGIN, ""),
                           dry_run=False)
    assert manifest["result"] == "STAGED_ONLY"
    release = releases / q.SOURCE_SHA
    cache = release / q.CACHE_RELATIVE
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(importlib.util.MAGIC_NUMBER + b"fixture-pyc-test")
    quarantine = tmp_path / "NoteriWorkerPool" / "quarantine" / q.SOURCE_SHA
    return source, release, cache, quarantine


def call(source, release, quarantine, **kwargs):
    opts = {"source": source, "release": release, "quarantine": quarantine,
            "hostname": "Noteri", "profile": "NORMAL", "platform": "nt",
            "mode": "plan", "inactive": True,
            "inspect_git": lambda _: (q.SOURCE_SHA, ORIGIN, "")}
    opts.update(kwargs)
    return q.operate(**opts)


def test_plan_is_readonly_and_reports_single_fixed_cache(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    original = cache.read_bytes()
    result = call(source, release, quarantine)
    assert result["result"] == "QUARANTINE_PLAN_READY"
    assert result["cache_relative"] == q.CACHE_LABEL
    assert result["cache_sha256"] == stage.file_sha256(cache)
    assert result["state_changed"] is False
    assert result["activated"] is False
    assert result["secrets_read"] is False
    assert not quarantine.exists()
    assert cache.read_bytes() == original
    assert not (quarantine.parent / ".cache-quarantine.lock").exists()


def test_quarantine_replay_and_restore_without_deleting_cache(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    original = cache.read_bytes()
    first = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert first["result"] == "CACHE_QUARANTINED"
    assert first["state_changed"] is True
    assert first["backup_preserved"] is True
    assert first["release_intact"] is True
    assert not cache.exists()
    assert len(list(quarantine.iterdir())) == 1
    assert list(quarantine.iterdir())[0].read_bytes() == original
    assert stage.validate_staged(
        release, stage.build_manifest(q.SOURCE_SHA, stage.safe_source_files(source)))
    assert not (quarantine.parent / ".cache-quarantine.lock").exists()
    replay = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert replay["result"] == "ALREADY_QUARANTINED"
    assert replay["state_changed"] is False
    assert len(list(quarantine.iterdir())) == 1
    restored = call(source, release, quarantine, mode="restore", confirm=q.RESTORE_CONFIRM)
    assert restored["result"] == "CACHE_RESTORED"
    assert restored["state_changed"] is True
    assert cache.read_bytes() == original
    assert list(quarantine.iterdir()) == []
    assert not (quarantine.parent / ".cache-quarantine.lock").exists()


@pytest.mark.parametrize("override,denial", [
    ({"hostname": "Desktop"}, "BLOCKED_HOST_PROFILE"),
    ({"profile": "ESTUDO"}, "BLOCKED_HOST_PROFILE"),
    ({"platform": "posix"}, "BLOCKED_HOST_PROFILE"),
    ({"mode": "quarantine", "inactive": False, "confirm": q.CONFIRM},
     "BLOCKED_SERVICE_NOT_ATTESTED_IDLE"),
    ({"mode": "quarantine", "confirm": "wrong"}, "BLOCKED_CONFIRMATION"),
    ({"mode": "restore", "confirm": q.CONFIRM}, "BLOCKED_CONFIRMATION"),
    ({"inspect_git": lambda _: ("a"*40, ORIGIN, "")}, "BLOCKED_GOVERNED_QUARANTINE"),
])
def test_denials_leave_release_unchanged(tmp_path, override, denial):
    source, release, cache, quarantine = fixture(tmp_path)
    original = cache.read_bytes()
    result = call(source, release, quarantine, **override)
    assert result["result"] == denial
    assert cache.read_bytes() == original
    assert not quarantine.exists()


def test_plan_remains_readonly_when_idle_is_unverified(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    result = call(source, release, quarantine, inactive=False)
    assert result["result"] == "QUARANTINE_PLAN_READY"
    assert cache.is_file()
    assert not quarantine.exists()


def test_other_extra_file_blocks_even_if_cache_matches(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    extra = release / "app" / "unexpected.py"
    extra.write_text("not allowed", encoding="utf-8")
    result = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert extra.exists() and cache.exists() and not quarantine.exists()


def test_modified_official_file_blocks_move(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    (release / "app" / "main.py").write_text("tampered", encoding="utf-8")
    result = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert cache.exists() and not quarantine.exists()


def test_cache_magic_mismatch_blocks_without_new_file(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    cache.write_bytes(b"NOT-A-PYC")
    result = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert cache.exists() and not quarantine.exists()


def test_exclusive_lock_blocks_concurrent_move(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    quarantine.parent.mkdir(parents=True)
    lock = quarantine.parent / ".cache-quarantine.lock"
    lock.write_text("another-owner", encoding="utf-8")
    result = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert result["state_may_have_changed"] is True
    assert cache.is_file() and not quarantine.exists()
    assert lock.read_text(encoding="utf-8") == "another-owner"


def test_backup_tamper_blocks_replay_and_restore(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    assert call(source, release, quarantine, mode="quarantine",
                confirm=q.CONFIRM)["result"] == "CACHE_QUARANTINED"
    file = next(quarantine.iterdir())
    file.write_bytes(b"tampered")
    for mode, confirm in (("quarantine", q.CONFIRM), ("restore", q.RESTORE_CONFIRM)):
        result = call(source, release, quarantine, mode=mode, confirm=confirm)
        assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert not cache.exists()
    assert file.read_bytes() == b"tampered"


def test_symlink_cache_is_rejected_before_move(tmp_path):
    source, release, cache, quarantine = fixture(tmp_path)
    cache.unlink()
    try:
        cache.symlink_to(source / "app" / "main.py")
    except (OSError, NotImplementedError):
        pytest.skip("Symlink privilege unavailable")
    result = call(source, release, quarantine, mode="quarantine", confirm=q.CONFIRM)
    assert result["result"] == "BLOCKED_GOVERNED_QUARANTINE"
    assert not quarantine.exists()


def test_cli_has_only_fixed_mode_confirmation_and_no_generic_path():
    script = (Path(__file__).resolve().parents[1] / "scripts" /
              "noteri_worker_pool_cache_quarantine.py").read_text(encoding="utf-8")
    assert script.count("parser.add_argument(") == 2
    assert 'parser.add_argument("--mode"' in script
    assert 'parser.add_argument("--confirm"' in script
    assert "subprocess." not in script
    assert "shell=True" not in script
    assert "shutil.rmtree" not in script
    assert "os.remove(" not in script
    assert "os.unlink(" not in script


@pytest.mark.parametrize("listener,task,expected", [
    (True, True, True),
    (False, True, False),
    (True, False, False),
    (False, False, False),
])
def test_independent_native_idle_probes(listener, task, expected):
    seen = []
    result = q.native_idle_status(
        hostname="Noteri", platform="nt",
        listener_probe=lambda: seen.append("listener") or listener,
        task_probe=lambda: seen.append("task") or task)
    assert seen == ["listener", "task"]
    assert result["native_listener_absent"] is listener
    assert result["native_task_absent"] is task
    assert result["native_idle_attested"] is expected


def test_native_probe_errors_fail_closed_and_do_not_skip_other_probe():
    seen = []

    def unavailable():
        seen.append("listener")
        raise OSError("synthetic probe error")

    state = q.native_idle_status(
        hostname="Noteri", platform="nt", listener_probe=unavailable,
        task_probe=lambda: seen.append("task") or True)
    assert seen == ["listener", "task"]
    assert state == {"native_listener_absent": False,
                     "native_task_absent": True, "native_idle_attested": False}
    blocked = q.native_idle_status(
        hostname="Desktop", platform="nt",
        listener_probe=lambda: pytest.fail("called on wrong host"),
        task_probe=lambda: pytest.fail("called on wrong host"))
    assert blocked["native_idle_attested"] is False


def test_detailed_service_status_keeps_unknown_distinct_from_absent():
    state = q.detailed_service_status(
        hostname="Noteri", platform="nt",
        socket_probe=lambda: "listening_unverified",
        schtasks_probe=lambda: "absent_or_unreadable")
    assert state == {"native_socket_status": "listening_unverified",
                     "native_schtasks_status": "absent_or_unreadable"}
    state = q.detailed_service_status(
        hostname="Noteri", platform="nt",
        socket_probe=lambda: "not_listening",
        schtasks_probe=lambda: "present_unverified")
    assert state == {"native_socket_status": "not_listening",
                     "native_schtasks_status": "present_unverified"}


def test_detailed_service_probe_errors_are_not_treated_as_absence():
    def fail():
        raise OSError("synthetic")

    assert q.detailed_service_status(
        hostname="Noteri", platform="nt", socket_probe=fail,
        schtasks_probe=fail) == {
            "native_socket_status": "unknown",
            "native_schtasks_status": "unknown",
        }
    assert q.detailed_service_status(
        hostname="Noteri", platform="nt",
        socket_probe=lambda: "unexpected",
        schtasks_probe=lambda: "unexpected") == {
            "native_socket_status": "unknown",
            "native_schtasks_status": "unknown",
        }
