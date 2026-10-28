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
        "failure": {"type": "RuntimeReplaceabilityError", "category": "acl_denied"},
    }).encode())
    return root, original_sha, manifest_sha


def test_failure_readback_preserves_old_content_and_sanitizes_error(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "host_context", lambda: ("nt", "Noteri"))
    root, original, _ = _fixture(tmp_path)
    report = m.inventory(root, original, "0" * 64)
    assert report["phase"] == "replaceability_preflight"
    assert report["failure_category"] == "acl_denied"
    assert report["legacy_archive_matches"] is True
    assert report["backup_content_intact"] is True
    assert report["all_previous_content"] is True
    assert report["all_desired_content"] is False
    assert report["mutation_started"] is False
    assert "error" not in report


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
    assert "if: github.actor == 'ericson-j-santos' && inputs.mode == 'update'" in workflow
