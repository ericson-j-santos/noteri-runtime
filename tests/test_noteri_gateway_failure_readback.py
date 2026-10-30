import hashlib
import json
from pathlib import Path

import pytest

from scripts import noteri_gateway_failure_readback as m


def _put(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _fixture(tmp_path: Path, *, current: bytes = b"old") -> tuple[Path, str, str]:
    root = tmp_path / "gateway"
    root.mkdir()
    backup = root / ("backup-20261028-154300-" + "a" * 32)
    entries = {}
    for relative in m.MANAGED:
        old = b"old"
        new = b"new"
        _put(root / relative, current)
        _put(backup / "files" / relative, old)
        entries[relative] = {
            "existed": True,
            "previous_sha256": hashlib.sha256(old).hexdigest(),
            "previous_size": len(old),
            "desired_sha256": hashlib.sha256(new).hexdigest(),
            "desired_size": len(new),
        }
    manifest_sha = _put(
        backup / "rollback-manifest.json",
        json.dumps({"version": 2, "install_root": str(root.resolve()),
                    "entries": entries}).encode(),
    )
    original_sha = _put(backup / "legacy-update-receipt.json", b"original")
    _put(root / "update-receipt.json", json.dumps({
        "result": "HOST_UPDATE_BLOCKED", "source_commit": "7d6ec0742ce9570408e8f3673a4f3c65c6777eb0",
        "backup_dir": str(backup), "phase": "replaceability_preflight",
        "mutation_started": False, "rollback_attempted": False,
        "rollback_succeeded": None,
        "failure": {
            "type": "RuntimeReplaceabilityError",
            "category": "acl_denied",
            "operation": "activate_stage",
            "os_error": {
                "errno": 13,
                "winerror": 5,
                "strerror": r"C:\\sensitive\\path",
            },
            "raw_error": "must-not-leak",
        },
    }).encode())
    return root, original_sha, manifest_sha


def _write_current_recovery(root: Path, transaction_id: str) -> None:
    receipt = json.loads((root / "update-receipt.json").read_text())
    receipt["source_commit"] = m.CURRENT_DIAGNOSTIC_RULES_SHA
    receipt["transaction_id"] = transaction_id
    receipt["primary_receipt_error"] = "PermissionError"
    _put(
        root / f"update-recovery-{transaction_id}.json",
        json.dumps(receipt).encode(),
    )


def test_failure_readback_preserves_old_content_and_sanitizes_error(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    report = m.inventory(root, original, "0" * 64)
    assert report["phase"] == "replaceability_preflight"
    assert report["failure_category"] == "acl_denied"
    assert report["failure_operation"] == "activate_stage"
    assert report["failure_os_error"] == {"errno": 13, "winerror": 5}
    assert "strerror" not in json.dumps(report)
    assert "must-not-leak" not in json.dumps(report)
    assert report["legacy_archive_matches"] is True
    assert report["backup_content_intact"] is True
    assert report["all_previous_content"] is True
    assert report["all_desired_content"] is False
    assert report["mutation_started"] is False
    assert "error" not in report



def test_current_rules_receipt_requires_operation_and_os_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    receipt_path = root / "update-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["source_commit"] = m.CURRENT_DIAGNOSTIC_RULES_SHA
    receipt["failure"].pop("operation")
    receipt["failure"].pop("os_error")
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(m.ReadbackBlocked, match="FAILURE_OPERATION_INVALID"):
        m.inventory(root, original, "0" * 64)


def test_failure_readback_prefers_current_fallback_recovery_receipt(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    primary_sha = hashlib.sha256((root / "update-receipt.json").read_bytes()).hexdigest()
    _write_current_recovery(root, "b" * 32)
    report = m.inventory(root, original, "0" * 64, primary_sha)
    assert report["receipt_origin"] == "recovery"
    assert report["source_commit"] == m.CURRENT_DIAGNOSTIC_RULES_SHA
    assert report["primary_receipt_source_commit"] == "7d6ec0742ce9570408e8f3673a4f3c65c6777eb0"
    assert report["failure_operation"] == "activate_stage"
    assert report["all_previous_content"] is True


def test_failure_readback_rejects_tampered_primary_for_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    primary = root / "update-receipt.json"
    expected_primary_sha = hashlib.sha256(primary.read_bytes()).hexdigest()
    _write_current_recovery(root, "b" * 32)
    primary.write_bytes(primary.read_bytes() + b"\n")
    with pytest.raises(m.ReadbackBlocked, match="PRIMARY_RECEIPT_PIN_MISMATCH"):
        m.inventory(root, original, "0" * 64, expected_primary_sha)


def test_failure_readback_detects_late_recovery_ambiguity(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    primary_sha = hashlib.sha256((root / "update-receipt.json").read_bytes()).hexdigest()
    _write_current_recovery(root, "b" * 32)
    original_inventory = m._recovery_inventory
    calls = 0

    def changing_inventory(target):
        nonlocal calls
        calls += 1
        if calls == 2:
            _write_current_recovery(target, "c" * 32)
        return original_inventory(target)

    monkeypatch.setattr(m, "_recovery_inventory", changing_inventory)
    with pytest.raises(m.ReadbackBlocked, match="EVIDENCE_CHANGED"):
        m.inventory(root, original, "0" * 64, primary_sha)


def test_failure_readback_detects_stable_name_reclassification(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    primary_sha = hashlib.sha256((root / "update-receipt.json").read_bytes()).hexdigest()
    _write_current_recovery(root, "b" * 32)
    _write_current_recovery(root, "c" * 32)
    ignored = root / f"update-recovery-{'c' * 32}.json"
    ignored_receipt = json.loads(ignored.read_text())
    ignored_receipt["source_commit"] = m.EXPECTED_PRIMARY_SOURCE_COMMIT
    ignored.write_text(json.dumps(ignored_receipt), encoding="utf-8")
    original_evidence = m._recovery_evidence

    def reclassifying_evidence(target):
        changed = json.loads(ignored.read_text())
        changed["source_commit"] = m.CURRENT_DIAGNOSTIC_RULES_SHA
        ignored.write_text(json.dumps(changed), encoding="utf-8")
        return original_evidence(target)

    monkeypatch.setattr(m, "_recovery_evidence", reclassifying_evidence)
    with pytest.raises(m.ReadbackBlocked, match="EVIDENCE_CHANGED"):
        m.inventory(root, original, "0" * 64, primary_sha)


def test_failure_readback_rejects_ambiguous_current_recoveries(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    _write_current_recovery(root, "b" * 32)
    _write_current_recovery(root, "c" * 32)
    with pytest.raises(m.ReadbackBlocked, match="RECOVERY_RECEIPT_AMBIGUOUS"):
        m.inventory(root, original, "0" * 64)


def test_failure_readback_reports_divergent_content_without_false_success(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path, current=b"new")
    report = m.inventory(root, original, "0" * 64)
    assert report["all_previous_content"] is False
    assert report["all_desired_content"] is True


def test_failure_readback_fails_closed_on_wrong_host_or_snapshot(tmp_path, monkeypatch):
    root, original, _ = _fixture(tmp_path)
    monkeypatch.setattr(m, "host_context", lambda: ("posix", "Noteri"))
    with pytest.raises(m.ReadbackBlocked, match="NOTERI_WINDOWS_REQUIRED"):
        m.inventory(root, original, "0" * 64)
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    backup = next(root.glob("backup-*"))
    (backup / "rollback-manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(m.ReadbackBlocked, match="MANIFEST_INVALID"):
        m.inventory(root, original, "0" * 64)


def test_diagnostic_workflow_is_read_only_and_separate_from_update():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/noteri-command-gateway-refresh.yml").read_text()
    assert "options: [preflight, update, diagnose]" in workflow
    assert "if: inputs.mode == 'diagnose'" in workflow
    assert "--risk', '1'" in workflow
    assert "noteri_gateway_failure_readback.py" in workflow
    assert "NOTERI_GATEWAY_FAILURE_INDEPENDENT_READBACK_OK" in workflow
    assert "failure_operation" in workflow
    assert "failure_os_error" in workflow
    assert '.receipt_origin == "recovery"' in workflow
    assert '.primary_receipt_sha256 == "4a0ee0fad909c63cb4cff89577720e5ee1cd4c9832cfe18e691e3555ba81c512"' in workflow
    assert "$syncRef = 'origin/main'" in workflow
    assert "if: github.actor == 'ericson-j-santos' && inputs.mode == 'update'" in workflow
