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
    release = str(tmp_path / "releases" / SHA / "scripts" / "noteri_control_plane_watchdog.py")
    runner = str(tmp_path / "runner")
    meta_path.write_text(json.dumps({
        "source_sha": SHA, "task": {"exists": True},
        "release_script": release, "runner_home": runner
    }), encoding="utf-8")
    monkeypatch.setattr(module.watchdog, "metadata_path", lambda: meta_path)
    args = module.subprocess.list2cmdline([release, "watch", "--runner-home", runner])
    digest = module.hashlib.sha256(args.encode("utf-8")).hexdigest()
    monkeypatch.setattr(module.launcher, "task_status", lambda: {
        "exists": True, "enabled": True, "trigger_at_startup": True, "logon_type": "S4U",
        "action_count": 1, "action_python_observed": True,
        "action_arguments_sha256": digest,
    })
    monkeypatch.setattr(module.launcher, "attest_installed_release", lambda *args: None)
    monkeypatch.setattr(module, "read_model_tags", lambda: {
        "status": "PRESENT", "present": True, "digest": "c" * 64,
    })
    monkeypatch.setattr(module, "worker_pool_readonly_probe", lambda *_: {
        "schema_version": 1, "token_reference_state": "PRESENT_ACL_UNVERIFIED",
        "loopback_8097_state": "TCP_CONNECTED_UNAUTHENTICATED",
        "token_bytes_read": False, "token_acl_verified": False,
        "contract_authenticated": False, "health_verified": False,
        "cost_zero_confirmed": False, "ready_for_work": False,
        "state_changed": False,
    })
    return meta_path


def test_inventory_reports_readonly_without_promoting_e2e(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _stub_inventory(monkeypatch, tmp_path)
    receipt = module.inventory(SHA, CORR, module.CONFIRM)
    assert receipt["installed_attested"] is True
    assert receipt["live_task_s4u"] is True
    assert receipt["live_task_action_attested"] is True
    assert receipt["profile"] == "NORMAL"
    assert receipt["model"]["present"] is True
    assert receipt["blocking_reasons"] == []
    assert receipt["state_changed"] is False
    assert receipt["ready_for_builder"] is False
    assert receipt["installation_authorized"] is False
    assert receipt["session_gateway_readback_required"] is True
    assert receipt["task_action_readback_required"] is True
    assert receipt["cost_zero_attestation_required"] is True
    assert receipt["worker_pool_readonly"]["ready_for_work"] is False
    assert receipt["worker_pool_readonly"]["contract_authenticated"] is False
    assert receipt["worker_pool_readonly"]["token_bytes_read"] is False



def test_task_action_uses_exact_release_and_runner_without_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    meta = _stub_inventory(monkeypatch, tmp_path)
    base = json.loads(meta.read_text(encoding="utf-8"))
    action = module.launcher.task_status()
    assert module.task_action_attested(base, action)
    # Um S4U saudavel com acao antiga ou comando divergente nao autoriza o host.
    for value in (
        {"action_arguments_sha256": "f" * 64},
        {"action_count": 2},
        {"action_python_observed": False},
        {"action_arguments_sha256": None},
    ):
        altered = dict(action, **value)
        assert not module.task_action_attested(base, altered)
        monkeypatch.setattr(module.launcher, "task_status", lambda report=altered: report)
        receipt = module.inventory(SHA, CORR, module.CONFIRM)
        assert receipt["live_task_s4u"] is True
        assert receipt["live_task_action_attested"] is False
        assert "TASK_ACTION_NOT_VERIFIED" in receipt["blocking_reasons"]
    assert json.loads(meta.read_text(encoding="utf-8")) == base


def test_task_status_action_xml_is_bound_and_rejects_extra_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"fixture-python")
    arguments = str(tmp_path / "watchdog.py") + " watch --runner-home runner"
    from xml.sax.saxutils import escape
    def observe(extra: str = ""):
        xml = ("<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>"
               "<Settings><Enabled>true</Enabled></Settings>"
               "<Principals><Principal><LogonType>S4U</LogonType></Principal></Principals>"
               "<Triggers><BootTrigger /></Triggers>"
               f"<Actions><Exec><Command>{escape(str(executable))}</Command>"
               f"<Arguments>{escape(arguments)}</Arguments></Exec>{extra}</Actions></Task>").encode()
        monkeypatch.setattr(module.launcher.subprocess, "run",
                            lambda *a, **k: SimpleNamespace(returncode=0, stdout=xml))
        return module.launcher.task_status()
    current = observe()
    assert current["action_python_observed"] is True
    assert current["action_count"] == 1
    assert current["action_arguments_sha256"] == module.hashlib.sha256(arguments.encode()).hexdigest()
    extra = "<ComHandler><ClassId>not-approved</ClassId></ComHandler>"
    assert observe(extra)["action_python_observed"] is False
    monkeypatch.setattr(module.launcher, "_path_is_redirect",
                        lambda path: path == executable)
    assert observe()["action_python_observed"] is False

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


def test_worker_pool_token_reference_shape_is_readonly(tmp_path: Path) -> None:
    path = tmp_path / "ReqSys" / "NoteriWorkerPool" / "credentials" / "api-token.txt"
    assert module.worker_token_reference_shape(None) == "HOST_CONTEXT_UNAVAILABLE"
    assert module.worker_token_reference_shape("relative") == "HOST_CONTEXT_INVALID"
    assert module.worker_token_reference_shape(str(tmp_path)) == "REFERENCE_MISSING"
    path.parent.mkdir(parents=True)
    path.mkdir()
    assert module.worker_token_reference_shape(str(tmp_path)) == "REFERENCE_NOT_REGULAR"
    path.rmdir()
    path.write_text("test fixture only", encoding="utf-8")
    assert module.worker_token_reference_shape(str(tmp_path)) == "PRESENT_ACL_UNVERIFIED"
    # No token bytes are read by this function, even when a regular file exists.
    assert path.read_text(encoding="utf-8") == "test fixture only"


def test_worker_pool_reference_symlink_and_missing_parent_block(tmp_path: Path) -> None:
    base = tmp_path / "ReqSys"
    external = tmp_path / "untrusted"
    external.mkdir()
    try:
        base.symlink_to(external, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert module.worker_token_reference_shape(str(tmp_path)) == "REFERENCE_REDIRECTED"


def test_worker_pool_loopback_only_fixed_tcp_no_auth() -> None:
    seen = []
    class Connection:
        def close(self):
            seen.append("closed")
        def send(self, *_):
            raise AssertionError("Network bytes must never be sent")
    def connected(address, timeout):
        seen.append((address, timeout))
        return Connection()
    receipt = module.worker_pool_readonly_probe("not-absolute", connect=connected)
    assert seen == [(("127.0.0.1", 8097), 0.25), "closed"]
    assert receipt["loopback_8097_state"] == "TCP_CONNECTED_UNAUTHENTICATED"
    assert receipt["token_reference_state"] == "HOST_CONTEXT_INVALID"
    for key in ("contract_authenticated", "health_verified", "cost_zero_confirmed",
                "ready_for_work", "token_bytes_read", "token_acl_verified",
                "state_changed"):
        assert receipt[key] is False


def test_worker_pool_tcp_failure_and_replay_are_nonpromoting(tmp_path: Path) -> None:
    def refused(address, timeout):
        assert address == ("127.0.0.1", 8097)
        raise ConnectionRefusedError("fixture")
    first = module.worker_pool_readonly_probe(str(tmp_path), connect=refused)
    second = module.worker_pool_readonly_probe(str(tmp_path), connect=refused)
    assert first == second
    assert first["token_reference_state"] == "REFERENCE_MISSING"
    assert first["loopback_8097_state"] == "TCP_NOT_REACHABLE"
    assert first["ready_for_work"] is False
