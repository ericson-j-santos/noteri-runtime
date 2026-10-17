from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

P = Path(__file__).resolve().parents[1] / "scripts" / "noteri_gateway_refresh.py"
S = importlib.util.spec_from_file_location("noteri_gateway_refresh", P)
m = importlib.util.module_from_spec(S)
sys.modules[S.name] = m
S.loader.exec_module(m)


def execution():
    return {
        "repository": m.EXPECTED_WORKFLOW_REPOSITORY,
        "workflow_sha": "a" * 40,
        "run_id": 123,
        "run_attempt": 1,
    }


def seed_current_receipt(monkeypatch, root: Path) -> dict:
    install = root / "install"
    monkeypatch.setattr(m, "INSTALL_ROOT", install)
    files = {}
    for relative in sorted(m.MANAGED_FILES):
        payload = ("payload:" + relative).encode()
        target = install.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        files[relative] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    backup = install / "backup-test"
    backup.mkdir(parents=True)
    (backup / "rollback-manifest.json").write_text("{}", encoding="utf-8")
    receipt = {
        "result": "HOST_UPDATE_OK",
        "source_commit": m.RULES_COMMIT,
        "rules_version": m.RULES_VERSION,
        "host": m.EXPECTED_HOST,
        "install_root": str(install),
        "backup_dir": str(backup),
        "validation_head": m.RULES_COMMIT,
        "files": files,
    }
    m.atomic_json(install / "update-receipt.json", receipt)
    return receipt


def test_contract_is_fixed():
    assert m.RULES_COMMIT == "92e927757c29396228d7c2a04bd3a0ebac21422c"
    assert m.RULES_VERSION == "1.6.11"
    assert m.INSTALL_ROOT == Path(r"C:\dev\chatgpt-command-gateway")
    assert m.INSTALL_SHA256 == "f73d843c86953e5f1eaca791850b5b10ccb670389cef722c2b7d921ff381f561"
    assert m.UPDATE_SHA256 == "fbed2c036415a4f97637c453c37e3060a580d549f68a519785d0a02926589103"


def test_rejects_other_host():
    with pytest.raises(m.RefreshError, match="host invalido"):
        m.validate("OTHER", m.CONFIRM, m.RULES_COMMIT)


def test_rejects_wrong_confirmation():
    with pytest.raises(m.RefreshError, match="confirmacao invalida"):
        m.validate("Noteri", "WRONG", m.RULES_COMMIT)


def test_rejects_wrong_commit():
    with pytest.raises(m.RefreshError, match="commit divergente"):
        m.validate("Noteri", m.CONFIRM, "0" * 40)


@pytest.mark.parametrize(
    ("repository", "workflow_sha", "run_id", "run_attempt"),
    [
        ("other/repo", "a" * 40, 1, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "bad", 1, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "a" * 40, 0, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "a" * 40, 1, 0),
    ],
)
def test_rejects_invalid_execution_identity(
    repository, workflow_sha, run_id, run_attempt
):
    with pytest.raises(m.RefreshError):
        m.validate_execution(repository, workflow_sha, run_id, run_attempt)


def test_non_admin_fails_before_fetch_or_write(monkeypatch):
    calls = {"fetch": 0, "write": 0}
    monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
    monkeypatch.setattr(m, "is_admin", lambda: False)
    monkeypatch.setattr(
        m,
        "fetch",
        lambda *_args: calls.__setitem__("fetch", calls["fetch"] + 1),
    )
    monkeypatch.setattr(
        m,
        "atomic_json",
        lambda *_args: calls.__setitem__("write", calls["write"] + 1),
    )
    with pytest.raises(m.RefreshError, match="elevacao obrigatoria"):
        m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution())
    assert calls == {"fetch": 0, "write": 0}


def test_current_receipt_is_verified_and_bound_to_execution(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        seed_current_receipt(monkeypatch, root)
        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: True)
        monkeypatch.setattr(
            m, "fetch", lambda *_args: pytest.fail("must not download")
        )
        result = m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution())
        assert result["result"] == "NOTERI_GATEWAY_ALREADY_CURRENT"
        bound = json.loads(
            (m.INSTALL_ROOT / "update-receipt.json").read_text(encoding="utf-8")
        )
        assert bound["workflow_repository"] == m.EXPECTED_WORKFLOW_REPOSITORY
        assert bound["workflow_sha"] == "a" * 40
        assert bound["workflow_run_id"] == 123
        assert bound["workflow_run_attempt"] == 1


def test_hash_divergence_fails_before_binding(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        receipt = seed_current_receipt(monkeypatch, root)
        target = m.INSTALL_ROOT / "bin" / "command_gateway.py"
        target.write_bytes(b"divergent")
        with pytest.raises(m.RefreshError, match="hash instalado divergente"):
            m.bind_execution(receipt, **execution())
        stored = json.loads(
            (m.INSTALL_ROOT / "update-receipt.json").read_text(encoding="utf-8")
        )
        assert "workflow_run_id" not in stored


def test_missing_rollback_snapshot_fails_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt = seed_current_receipt(monkeypatch, Path(tmp))
        Path(receipt["backup_dir"], "rollback-manifest.json").unlink()
        with pytest.raises(m.RefreshError, match="backup de rollback"):
            m.verify_update_receipt(receipt)


def test_atomic_json_removes_only_owned_temp_on_replace_failure(
    monkeypatch,
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "receipt.json"
        monkeypatch.setattr(
            m.os,
            "replace",
            lambda *_args: (_ for _ in ()).throw(
                PermissionError("injected-replace-failure")
            ),
        )
        with pytest.raises(PermissionError, match="injected-replace-failure"):
            m.atomic_json(path, {"ok": True})
        assert list(root.glob("receipt.json.tmp-*")) == []


def test_atomic_json_preserves_divergent_temp_on_replace_failure(
    monkeypatch,
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "receipt.json"

        def diverge(source, _destination):
            Path(source).write_bytes(b"divergent")
            raise PermissionError("injected-replace-failure")

        monkeypatch.setattr(m.os, "replace", diverge)
        with pytest.raises(PermissionError, match="injected-replace-failure"):
            m.atomic_json(path, {"ok": True})
        leftovers = list(root.glob("receipt.json.tmp-*"))
        assert len(leftovers) == 1
        assert leftovers[0].read_bytes() == b"divergent"


def test_updater_failure_is_sanitized_and_never_bound(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        install = root / "install"
        install.mkdir()
        monkeypatch.setattr(m, "INSTALL_ROOT", install)
        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: True)
        monkeypatch.setattr(m, "load_update_receipt", lambda: None)
        monkeypatch.setattr(m, "fetch", lambda *_args: b"payload")
        monkeypatch.setattr(
            m.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(
                returncode=28, stderr="HOST_UPDATE_BLOCKED"
            ),
        )
        with pytest.raises(m.RefreshError, match="updater_failed:28"):
            m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution())
        assert not (install / "update-receipt.json").exists()
