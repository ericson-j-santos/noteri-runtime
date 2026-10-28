from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import noteri_gateway_legacy_pin_inventory as inv


def fixture(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(inv, "host_context", lambda: ("nt", "Noteri"))
    root = tmp_path / "install"
    backup = root / ("backup-20261028-010101-" + "a" * 32)
    backup.mkdir(parents=True)
    receipt = {
        "result": "HOST_UPDATE_BLOCKED",
        "source_commit": inv.LEGACY_SOURCE_COMMIT,
        "rollback_attempted": True,
        "rollback_succeeded": False,
        "backup_dir": str(backup),
    }
    manifest = {
        "version": 1,
        "install_root": str(root.resolve()),
        "entries": {name: {} for name in inv.MANAGED_FILES},
    }
    receipt_path = root / "update-receipt.json"
    manifest_path = backup / "rollback-manifest.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return root, receipt_path, manifest_path


def test_inventory_reports_only_pins_and_no_install_permission(tmp_path, monkeypatch):
    root, receipt, manifest = fixture(tmp_path, monkeypatch)
    before = (receipt.read_bytes(), manifest.read_bytes())
    result = inv.inventory(root)
    assert result == {
        "result": "NOTERI_LEGACY_PIN_INVENTORY",
        "receipt_sha256": hashlib.sha256(before[0]).hexdigest(),
        "manifest_sha256": hashlib.sha256(before[1]).hexdigest(),
        "legacy_state_confirmed": False,
        "installation_authorized": False,
        "managed_runtime_changed": False,
    }
    assert (receipt.read_bytes(), manifest.read_bytes()) == before


def test_inventory_fails_on_wrong_host_or_legacy_state(tmp_path, monkeypatch):
    root, receipt, _ = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(inv, "host_context", lambda: ("nt", "Other"))
    with pytest.raises(inv.PinInventoryBlocked, match="NOTERI_WINDOWS_REQUIRED"):
        inv.inventory(root)
    monkeypatch.setattr(inv, "host_context", lambda: ("nt", "Noteri"))
    data = json.loads(receipt.read_text())
    data["rollback_succeeded"] = True
    receipt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(inv.PinInventoryBlocked, match="LEGACY_RECEIPT_STATE_INVALID"):
        inv.inventory(root)


def test_inventory_rejects_reparse_and_outside_backup(tmp_path, monkeypatch):
    root, receipt, manifest = fixture(tmp_path, monkeypatch)
    manifest.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    manifest.symlink_to(outside)
    with pytest.raises(inv.PinInventoryBlocked, match="PATH_OUTSIDE_INSTALL_ROOT"):
        inv.inventory(root)
    manifest.unlink()
    data = json.loads(receipt.read_text())
    data["backup_dir"] = str(tmp_path / "outside")
    receipt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises((FileNotFoundError, inv.PinInventoryBlocked)):
        inv.inventory(root)
