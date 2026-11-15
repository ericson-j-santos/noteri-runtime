from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_watchdog_readonly_inventory.py"
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location("noteri_watchdog_readonly_inventory", SOURCE)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

SHA = "a" * 40
CORR = "todo39-noteri-inventory-20261106"


def test_host_and_input_guards_fail_closed() -> None:
    with pytest.raises(module.InventoryError, match="HOST_NOT_AUTHORIZED"):
        module.require_identity(host="DESKTOP-PDQK954", platform="nt")
    with pytest.raises(module.InventoryError, match="HOST_NOT_AUTHORIZED"):
        module.require_identity(host="Noteri", platform="posix")
    with pytest.raises(module.InventoryError, match="CONFIRMATION_INVALID"):
        module.inventory(SHA, CORR, "NO")
    with pytest.raises(module.InventoryError, match="EXPECTED_SHA_INVALID"):
        module.inventory("invalid", CORR, module.CONFIRM)
    with pytest.raises(module.InventoryError, match="CORRELATION_ID_INVALID"):
        module.inventory(SHA, "short", module.CONFIRM)


def test_metadata_does_not_follow_redirects(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    path = root / "metadata.json"
    path.write_text('{"source_sha":"ok"}', encoding="utf-8")
    assert module.safe_metadata(path)["source_sha"] == "ok"
    other = tmp_path / "elsewhere.json"
    other.write_text('{"source_sha":"not-trusted"}', encoding="utf-8")
    path.unlink()
    try:
        path.symlink_to(other)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink fixture unavailable: {type(exc).__name__}")
    with pytest.raises(module.InventoryError, match="METADATA_REDIRECTED"):
        module.safe_metadata(path)


def test_missing_oversize_and_invalid_metadata_fail_closed(tmp_path: Path) -> None:
    p = tmp_path / "metadata.json"
    with pytest.raises(module.InventoryError, match="METADATA_MISSING"):
        module.safe_metadata(p)
    p.write_bytes(b"x" * (module.MAX_METADATA_BYTES + 1))
    with pytest.raises(module.InventoryError, match="METADATA_TOO_LARGE"):
        module.safe_metadata(p)
    p.write_bytes(b"[]")
    with pytest.raises(module.InventoryError, match="METADATA_INVALID"):
        module.safe_metadata(p)


def test_model_tags_only_reports_pinned_model_with_valid_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 200
        def __init__(self, data):
            self.data = data
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, *_):
            return json.dumps(self.data).encode("utf-8")
    class Opener:
        def __init__(self, data):
            self.data = data
        def open(self, req, timeout):
            assert req.full_url == "http://127.0.0.1:11434/api/tags"
            assert req.get_method() == "GET"
            assert timeout == 3
            return Response(self.data)
    present = {"models": [{"name": "qwen2.5-coder:7b", "digest": "b" * 64}]}
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: Opener(present))
    assert module.read_model_tags() == {"status": "PRESENT", "present": True, "digest": "b" * 64}
    present["models"][0]["digest"] = "wrong"
    assert module.read_model_tags()["status"] == "INVALID_DIGEST"
    present["models"] = []
    assert module.read_model_tags()["status"] == "ABSENT"


def _stub_inventory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    scripts = tmp_path / "checkout" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "noteri_control_plane_watchdog.py").write_bytes(b"fixture")
    monkeypatch.setattr(module, "__file__", str(scripts / "noteri_watchdog_readonly_inventory.py"))
    monkeypatch.setattr(module, "require_identity", lambda **_: None)
    monkeypatch.setattr(module, "checkout_sha", lambda _: SHA)
    monkeypatch.setattr(module.watchdog, "runtime_profile", lambda: "NORMAL")
    meta_path = tmp_path / "metadata.json"
    meta_path.write_text(json.dumps({"source_sha": SHA, "task": {"exists": True}}), encoding="utf-8")
    monkeypatch.setattr(module.watchdog, "metadata_path", lambda: meta_path)
    monkeypatch.setattr(module.launcher, "task_status", lambda: {
        "exists": True, "enabled": True, "trigger_at_startup": True, "logon_type": "S4U",
    })
    monkeypatch.setattr(module.launcher, "attest_installed_release", lambda *args: None)
    monkeypatch.setattr(module, "read_installed_release_receipt", lambda _: {
        "installed_release_sha256": "d" * 64,
        "task_definition_sha256": "e" * 64,
        "task_action_verified": True,
    })
    monkeypatch.setattr(module, "read_model_tags", lambda: {
        "status": "PRESENT", "present": True, "digest": "c" * 64,
    })
    return meta_path


def test_inventory_reports_readonly_without_promoting_e2e(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _stub_inventory(monkeypatch, tmp_path)
    receipt = module.inventory(SHA, CORR, module.CONFIRM)
    assert receipt["installed_attested"] is True
    assert receipt["task_action_verified"] is True
    assert receipt["installed_release_sha256"] == "d" * 64
    assert receipt["task_definition_sha256"] == "e" * 64
    assert receipt["live_task_s4u"] is True
    assert receipt["profile"] == "NORMAL"
    assert receipt["model"]["present"] is True
    assert receipt["blocking_reasons"] == []
    assert receipt["state_changed"] is False
    assert receipt["ready_for_builder"] is False
    assert receipt["installation_authorized"] is False
    assert receipt["session_gateway_readback_required"] is True
    assert receipt["task_action_readback_required"] is True
    assert receipt["cost_zero_attestation_required"] is True


def test_stale_release_blocks_without_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    meta = _stub_inventory(monkeypatch, tmp_path)
    original = meta.read_bytes()
    def reject(*args):
        raise module.launcher.LauncherError("WATCHDOG_INSTALLED_SHA_MISMATCH")
    monkeypatch.setattr(module.launcher, "attest_installed_release", reject)
    receipt = module.inventory(SHA, CORR, module.CONFIRM)
    assert receipt["installed_attested"] is False
    assert "WATCHDOG_INSTALLED_SHA_MISMATCH" in receipt["blocking_reasons"]
    assert receipt["ready_for_builder"] is False
    assert meta.read_bytes() == original


def test_estudo_stays_ineligible_but_control_is_readonly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _stub_inventory(monkeypatch, tmp_path)
    monkeypatch.setattr(module.watchdog, "runtime_profile", lambda: "ESTUDO")
    receipt = module.inventory(SHA, CORR, module.CONFIRM)
    assert "PROFILE_NOT_NORMAL" in receipt["blocking_reasons"]
    assert receipt["state_changed"] is False


def test_wrong_checkout_rejected_before_reading_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _stub_inventory(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "checkout_sha", lambda _: "d" * 40)
    monkeypatch.setattr(module.watchdog, "metadata_path", lambda: pytest.fail("read_runtime"))
    with pytest.raises(module.InventoryError, match="SOURCE_SHA_MISMATCH"):
        module.inventory(SHA, CORR, module.CONFIRM)


def test_corrupted_watchdog_metadata_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    path = _stub_inventory(monkeypatch, tmp_path)
    before = path.read_bytes()
    def malformed(*args):
        raise AttributeError("untrusted_runtime_path")
    monkeypatch.setattr(module.launcher, "attest_installed_release", malformed)
    monkeypatch.setattr(module.launcher, "task_status", lambda: None)
    receipt = module.inventory(SHA, CORR, module.CONFIRM)
    assert receipt["installed_attested"] is False
    assert "WATCHDOG_ATTESTATION_FAILED" in receipt["blocking_reasons"]
    assert "TASK_S4U_NOT_VERIFIED" in receipt["blocking_reasons"]
    assert "untrusted_runtime_path" not in json.dumps(receipt)
    assert receipt["ready_for_builder"] is False
    assert path.read_bytes() == before


def test_task_action_failure_does_not_promote_readback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    meta = _stub_inventory(monkeypatch, tmp_path)
    before = meta.read_bytes()
    def blocked(_):
        raise module.InventoryError("INSTALLED_TASK_ACTION_NOT_BOUND")
    monkeypatch.setattr(module, "read_installed_release_receipt", blocked)
    result = module.inventory(SHA, CORR, module.CONFIRM)
    assert result["task_action_verified"] is False
    assert result["installed_release_sha256"] is None
    assert "INSTALLED_TASK_ACTION_NOT_BOUND" in result["blocking_reasons"]
    assert result["ready_for_builder"] is False
    assert result["state_changed"] is False
    assert meta.read_bytes() == before


def test_installed_sha_invalid_before_runtime_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module.watchdog, "runtime_root", lambda: pytest.fail("runtime_read"))
    with pytest.raises(module.InventoryError, match="INSTALLED_SHA_INVALID"):
        module.read_installed_release_receipt({"source_sha": "../bad"})


def test_readonly_receipt_checks_real_release_and_task_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    import hashlib
    from types import SimpleNamespace
    runtime = tmp_path / "runtime"
    release = runtime / "releases" / SHA / "scripts" / "noteri_control_plane_watchdog.py"
    release.parent.mkdir(parents=True)
    release.write_bytes(b"installed-binary")
    digest = hashlib.sha256(b"installed-binary").hexdigest()
    monkeypatch.setattr(module.watchdog, "runtime_root", lambda: runtime)
    monkeypatch.setattr(module.watchdog, "validate_runner_home", lambda _: tmp_path / "runner")
    monkeypatch.setattr(module.watchdog, "schtasks_path", lambda: Path("schtasks.exe"))
    meta = {
        "source_sha": SHA, "release_script": str(release),
        "release_sha256": digest, "runner_home": str(tmp_path / "runner"),
    }
    xml = b"<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'><Principals><Principal><LogonType>S4U</LogonType></Principal></Principals><Triggers><BootTrigger/></Triggers><Actions><Exec><Arguments>ignored</Arguments></Exec></Actions></Task>"
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=xml))
    # The task contract belongs to the already-tested upgrade module; it must
    # reject arbitrary actions. No fake successful binding is accepted here.
    with pytest.raises(module.InventoryError, match="INSTALLED_TASK_ACTION_NOT_BOUND"):
        module.read_installed_release_receipt(meta)
    assert release.read_bytes() == b"installed-binary"

