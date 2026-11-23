from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
P = SCRIPTS / "noteri_gateway_update_preflight.py"
SPEC = importlib.util.spec_from_file_location("noteri_gateway_update_preflight", P)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def test_v2_inventory_is_read_only_and_non_promoting(monkeypatch):
    receipt = {"result": "HOST_UPDATE_OK"}
    monkeypatch.setattr(preflight.os, "name", "nt")
    monkeypatch.setattr(preflight.socket, "gethostname", lambda: "Noteri")
    monkeypatch.setattr(preflight.refresh, "read_update_receipt", lambda: (receipt, b"x"))
    monkeypatch.setattr(
        preflight.refresh,
        "verify_previous_v2_receipt",
        lambda value: {
            "source_commit": "1" * 40,
            "receipt_sha256": "a" * 64,
            "files": {},
        },
    )
    report = preflight.inventory()
    assert report == {
        "result": "NOTERI_GATEWAY_UPDATE_PREFLIGHT",
        "update_mode": "standard_v2",
        "source_commit": "1" * 40,
        "receipt_sha256": "a" * 64,
        "manifest_sha256": None,
        "installation_authorized": False,
        "managed_runtime_changed": False,
    }


def test_legacy_inventory_is_reused_without_authorizing_install(monkeypatch):
    monkeypatch.setattr(preflight.os, "name", "nt")
    monkeypatch.setattr(preflight.socket, "gethostname", lambda: "Noteri")
    monkeypatch.setattr(preflight.refresh, "read_update_receipt", lambda: None)
    monkeypatch.setattr(
        preflight.legacy,
        "inventory",
        lambda _root: {"receipt_sha256": "a" * 64, "manifest_sha256": "b" * 64},
    )
    report = preflight.inventory()
    assert report["update_mode"] == "legacy_v1_rebaseline"
    assert report["installation_authorized"] is False
    assert report["managed_runtime_changed"] is False


def test_main_fails_closed_with_sanitized_reason(monkeypatch, capsys):
    monkeypatch.setattr(
        preflight, "inventory", lambda: (_ for _ in ()).throw(
            preflight.refresh.RefreshError("STATE_INVALID")
        )
    )
    assert preflight.main() == 3
    assert json.loads(capsys.readouterr().out)["reason"] == "STATE_INVALID"
