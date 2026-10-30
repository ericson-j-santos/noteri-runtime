"""Regressões forenses: journal e ACL/ADS não podem produzir falso sucesso."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import noteri_gateway_forensic_inventory as f


def _put(path: Path, raw: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _fixture(tmp_path: Path, monkeypatch) -> tuple[Path, Path, dict]:
    root = tmp_path / "gateway"
    root.mkdir()
    backup = root / ("backup-20261028-154300-" + "a" * 32)
    entries = {}
    for name in sorted(f.baseline.MANAGED):
        previous = (name + ":previous").encode()
        desired = (name + ":desired").encode()
        _put(root / name, previous)
        _put(backup / "files" / name, previous)
        entries[name] = {
            "existed": True,
            "previous_sha256": hashlib.sha256(previous).hexdigest(),
            "previous_size": len(previous),
            "desired_sha256": hashlib.sha256(desired).hexdigest(),
            "desired_size": len(desired),
            "previous_windows_state": {"test": "expected"},
        }
    manifest = {
        "version": 2, "metadata_contract": f.WINDOWS_CONTRACT,
        "install_root": str(root.resolve()), "entries": entries,
    }
    manifest_digest = _put(backup / "rollback-manifest.json", json.dumps(manifest).encode())
    # O recibo antigo é um pin imutável: o teste não finge conhecer seus bytes.
    _put(root / "update-receipt.json", json.dumps({
        "result": "HOST_UPDATE_BLOCKED",
        "source_commit": f.FAILED_RULES_SHA,
        "phase": "install_runtime",
        "failure": {"type": "PermissionError", "category": "acl_denied"},
        "transaction_id": "b" * 32,
        "mutation_started": True,
        "rollback_attempted": True,
        "rollback_succeeded": True,
        "backup_dir": str(backup),
    }).encode())
    _put(root / "update-transaction.json", json.dumps({
        "version": 1, "transaction_id": "b" * 32,
        "source_commit": f.FAILED_RULES_SHA,
        "backup_dir": str(backup),
    }).encode())
    monkeypatch.setattr(f.baseline, "host_context", lambda: ("nt", "Noteri"))
    monkeypatch.setattr(f, "ROLLBACK_V2_SHA256", manifest_digest)

    helper = SimpleNamespace(
        _validate_windows_persisted_state=lambda expected, name: (
            None if expected == {"test": "expected"} else pytest.fail("snapshot divergiu")
        ),
        _windows_persisted_file_state=lambda path: {"ok": True},
        _windows_persisted_state_equivalent=lambda expected, actual: actual["ok"],
    )
    monkeypatch.setattr(f, "_canonical_helper", lambda _path: helper)
    return root, backup, {"helper": helper}


def test_read_only_forensic_receipt_rechecks_journal_and_windows_metadata(tmp_path, monkeypatch):
    root, backup, _ = _fixture(tmp_path, monkeypatch)
    paths = sorted(p for p in root.rglob("*") if p.is_file())
    original = {str(p): p.read_bytes() for p in paths}
    report = f.inspect(root, tmp_path / "helper")
    assert report["result"] == "NOTERI_GATEWAY_FORENSIC_READONLY"
    assert report["journal_bound_to_incident"] is True
    assert report["all_previous_content"] is True
    assert report["all_previous_windows_metadata"] is True
    assert report["backup_windows_metadata_intact"] is True
    assert report["metadata_checked_files"] == len(f.baseline.MANAGED)
    assert report["metadata_assessment"] == "MATCH"
    assert report["recovery_authorized"] is False
    assert report["host_ready"] is False
    assert report["managed_runtime_changed"] is False
    assert {str(p): p.read_bytes() for p in paths} == original


def test_wrong_journal_transaction_blocks_before_metadata(tmp_path, monkeypatch):
    root, _, _ = _fixture(tmp_path, monkeypatch)
    journal = root / "update-transaction.json"
    data = json.loads(journal.read_text())
    data["transaction_id"] = "c" * 32
    journal.write_text(json.dumps(data))
    with pytest.raises(f.baseline.ReadbackBlocked, match="JOURNAL_BINDING_INVALID"):
        f.inspect(root, tmp_path / "helper")


def test_unauthenticated_journal_backup_path_rejected(tmp_path, monkeypatch):
    root, _, _ = _fixture(tmp_path, monkeypatch)
    journal = root / "update-transaction.json"
    data = json.loads(journal.read_text())
    data["backup_dir"] = str(tmp_path / "other")
    journal.write_text(json.dumps(data))
    with pytest.raises(f.baseline.ReadbackBlocked, match="JOURNAL_BINDING_INVALID"):
        f.inspect(root, tmp_path / "helper")


def test_missing_journal_fails_closed(tmp_path, monkeypatch):
    root, _, _ = _fixture(tmp_path, monkeypatch)
    (root / "update-transaction.json").unlink()
    with pytest.raises(f.baseline.ReadbackBlocked, match="FILE_MISSING"):
        f.inspect(root, tmp_path / "helper")


def test_windows_acl_ads_divergence_is_not_accepted_as_recovery(tmp_path, monkeypatch):
    root, backup, fixture = _fixture(tmp_path, monkeypatch)
    fixture["helper"]._windows_persisted_file_state = lambda path: {
        "ok": "backup-" in str(path)
    }
    result = f.inspect(root, tmp_path / "helper")
    assert result["all_previous_content"] is True
    assert result["all_previous_windows_metadata"] is False
    assert result["backup_windows_metadata_intact"] is True
    assert result["metadata_assessment"] == "DIVERGENT"
    assert result["host_ready"] is False
    assert result["recovery_authorized"] is False


def test_malformed_windows_snapshot_blocks(tmp_path, monkeypatch):
    root, _, fixture = _fixture(tmp_path, monkeypatch)
    def reject_snapshot(_expected, _name):
        raise ValueError("fake raw sid must never escape")
    fixture["helper"]._validate_windows_persisted_state = reject_snapshot
    with pytest.raises(f.baseline.ReadbackBlocked, match="ROLLBACK_METADATA_SCHEMA_INVALID"):
        f.inspect(root, tmp_path / "helper")


def test_other_host_cannot_run_forensic_inspection(tmp_path, monkeypatch):
    root, _, _ = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(f.baseline, "host_context", lambda: ("posix", "Noteri"))
    with pytest.raises(f.baseline.ReadbackBlocked, match="NOTERI_WINDOWS_REQUIRED"):
        f.inspect(root, tmp_path / "helper")


def test_helper_path_and_hash_fail_closed_without_import(tmp_path):
    location = tmp_path / "_rules" / "scripts" / "install_command_gateway_host.py"
    _put(location, b"raise RuntimeError('untrusted')\n")
    with pytest.raises(f.baseline.ReadbackBlocked, match="CANONICAL_HELPER_HASH_INVALID"):
        f._canonical_helper(location)
    with pytest.raises(f.baseline.ReadbackBlocked, match="CANONICAL_HELPER_LOCATION_INVALID"):
        f._canonical_helper(tmp_path / "unexpected.py")


def test_forensic_workflow_is_manual_risk1_and_never_updater():
    text = (Path(__file__).resolve().parents[1] / ".github/workflows/noteri-gateway-forensic-readonly.yml").read_text()
    assert "  workflow_dispatch:" in text
    assert "  push:" not in text and "  schedule:" not in text
    assert "--require-runner-version-preflight" in text
    assert "SESSION_LAUNCH_OK" in text and "state_validated" in text
    assert "--risk', '1'" in text
    assert "noteri_gateway_forensic_inventory.py" in text
    assert "NOTERI_GATEWAY_FORENSIC_INDEPENDENT_READBACK_OK" in text
    assert "inputs.expected_workflow_sha" in text
    assert "update_command_gateway_host.py" not in text
    assert "REFRESH-NOTERI-COMMAND-GATEWAY" not in text


def test_backup_bytes_divergence_cannot_be_reported_as_match(tmp_path, monkeypatch):
    root, backup, _ = _fixture(tmp_path, monkeypatch)
    target = backup / "files" / sorted(f.baseline.MANAGED)[0]
    target.write_bytes(b"tampered-backup")
    report = f.inspect(root, tmp_path / "helper")
    assert report["all_previous_content"] is True
    assert report["backup_content_intact"] is False
    assert report["metadata_assessment"] == "DIVERGENT"
    assert report["host_ready"] is False


def test_windows_metadata_changes_during_inspection_fail_closed(tmp_path, monkeypatch):
    root, _, fixture = _fixture(tmp_path, monkeypatch)
    calls = {}

    def changing_metadata(path):
        key = str(path)
        calls[key] = calls.get(key, 0) + 1
        return {"ok": True, "sequence": calls[key]}

    fixture["helper"]._windows_persisted_file_state = changing_metadata
    with pytest.raises(f.baseline.ReadbackBlocked, match="WINDOWS_METADATA_CHANGED"):
        f.inspect(root, tmp_path / "helper")
