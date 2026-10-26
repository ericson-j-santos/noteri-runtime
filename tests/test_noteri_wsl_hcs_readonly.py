"""HCS read-only status gates; no WSL command, VM, service or host API called."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "noteri_wsl_hcs_readonly.py"
spec = importlib.util.spec_from_file_location("noteri_wsl_hcs_readonly", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

WSL_VM = {
    "Id": "{77777777-7777-4777-8777-777777777777}",
    "Name": "sensitive-machine",
    "Owner": "WSL",
    "SystemType": "VirtualMachine",
    "RuntimeOsType": "Linux",
    "State": "Running",
}
NON_WSL_VM = dict(WSL_VM, Owner="unrelated-product", Id="sensitive-other")
STOPPED_WSL_VM = dict(WSL_VM, State="Stopped")


def collect(rows):
    return probe.collect(platform_name="win32", hostname="Noteri", enumerator=lambda: rows)


def test_positive_is_vm_candidate_not_distro_startup_authority():
    result = collect([WSL_VM, NON_WSL_VM])
    assert result["system_count"] == 2
    assert result["linux_vm_running_count"] == 2
    assert result["wsl_vm_running_candidate_count"] == 1
    assert result["wsl_vm_candidate_observed"] is True
    assert result["ubuntu_distro_running_verified"] is False
    assert result["posix_transport_verified"] is False
    assert result["postgresql_verified"] is False
    assert result["agent_qwen_autonomous_verified"] is False
    assert result["guest_started"] is False
    assert result["state_changed"] is False
    assert "sensitive-machine" not in json.dumps(result)
    assert "77777777" not in json.dumps(result)


def test_other_vm_and_stopped_vm_never_count_as_running_wsl():
    result = collect([NON_WSL_VM, STOPPED_WSL_VM])
    assert result["system_count"] == 2
    assert result["wsl_vm_running_candidate_count"] == 0
    assert result["ubuntu_distro_running_verified"] is False


def test_empty_enumeration_does_not_claim_ubuntu_stopped():
    result = collect([])
    assert result["wsl_vm_candidate_observed"] is False
    assert result["ubuntu_distro_running_verified"] is False
    assert result["linux_vm_running_count"] == 0


@pytest.mark.parametrize(("platform", "host"), [
    ("linux", "Noteri"), ("win32", "Other"), ("win32", ""),
])
def test_wrong_platform_or_host_rejected_before_enum(platform, host):
    calls = []
    with pytest.raises(probe.Blocked, match="NOTERI_WINDOWS_REQUIRED"):
        probe.collect(platform_name=platform, hostname=host,
                      enumerator=lambda: calls.append("called"))
    assert calls == []


@pytest.mark.parametrize("rows", [
    None, {}, {"systems": []}, "[]", [""], [1], [{}],
    [{"Owner": "", "SystemType": "", "State": "", "RuntimeOsType": 10}],
    [WSL_VM] * (probe.MAX_SYSTEMS + 1),
])
def test_malformed_untrusted_hcs_results_are_blocked(rows):
    with pytest.raises(probe.Blocked):
        collect(rows)


def test_missing_optional_hcs_fields_are_reported_but_not_falsely_ready():
    row = {"SystemType": "VirtualMachine", "State": "Running"}
    output = collect([row])
    assert output["system_count"] == 1
    assert output["metadata_incomplete_count"] == 1
    assert output["wsl_vm_candidate_observed"] is False
    assert output["ubuntu_distro_running_verified"] is False


def test_replay_is_stable_and_no_external_side_effects():
    calls = []
    def enumerator():
        calls.append("enumerate")
        return [WSL_VM]
    first = probe.collect(platform_name="win32", hostname="Noteri", enumerator=enumerator)
    second = probe.collect(platform_name="win32", hostname="Noteri", enumerator=enumerator)
    assert first == second
    assert calls == ["enumerate", "enumerate"]


def test_casefold_owner_and_state_are_required_not_only_linux():
    bad = dict(WSL_VM, State="unknown")
    assert collect([bad])["wsl_vm_running_candidate_count"] == 0
    good = dict(WSL_VM, Owner="wsl", State="running")
    assert collect([good])["wsl_vm_running_candidate_count"] == 1


def test_whitelisted_windows_hcs_api_without_launching_guest():
    source = SCRIPT.read_text(encoding="utf-8")
    for required in (
        "HcsCreateOperation", "HcsEnumerateComputeSystems",
        "HcsWaitForOperationResult", "HcsCloseOperation", "LocalFree",
    ):
        assert required in source
    for forbidden in (
        "HcsCreateComputeSystem", "HcsStartComputeSystem", "HcsOpenComputeSystem",
        "HcsCreateProcess", "WslLaunch", "wsl.exe", "shell=True",
        "subprocess.run", "StartService", "ControlService", "WslConfigureDistribution",
    ):
        assert forbidden not in source


def test_hcs_wait_allows_cold_enumeration_and_closes_operation(monkeypatch):
    calls = []

    class Function:
        def __init__(self, implementation):
            self.implementation = implementation

        def __call__(self, *args):
            return self.implementation(*args)

    class Core:
        HcsCreateOperation = Function(lambda *_: 123)
        HcsEnumerateComputeSystems = Function(lambda *_: 0)
        HcsWaitForOperationResult = Function(
            lambda operation, timeout, _document: calls.append(
                ("wait", operation, timeout)
            ) or 1
        )
        HcsCloseOperation = Function(lambda operation: calls.append(("close", operation)))

    class Kernel:
        LocalFree = Function(lambda *_: pytest.fail("no document was allocated"))

    monkeypatch.setattr(probe.sys, "platform", "win32")
    monkeypatch.setattr(
        probe.ctypes, "WinDLL",
        lambda name: Core() if name == "ComputeCore.dll" else Kernel(),
        raising=False,
    )

    with pytest.raises(probe.Blocked, match="^HCS_ENUMERATION_UNAVAILABLE$"):
        probe.enumerate_existing()

    assert probe.HCS_TIMEOUT_MS == 15_000
    assert calls == [("wait", 123, 15_000), ("close", 123)]


@pytest.mark.parametrize(("hresult", "reason"), [
    (0x80070005, "HCS_ACCESS_DENIED"),
    (0x8037011B, "HCS_ACCESS_DENIED"),
    (0x800705B4, "HCS_OPERATION_TIMEOUT"),
    (0x80370118, "HCS_OPERATION_TIMEOUT"),
    (0x8037011B - (1 << 32), "HCS_ACCESS_DENIED"),
    (1, "HCS_ENUMERATION_UNAVAILABLE"),
])
def test_hcs_failure_maps_only_documented_hresult_categories(hresult, reason):
    assert probe._hcs_failure(hresult) == reason


def test_arbitrary_cli_argument_denied_before_io(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["noteri_wsl_hcs_readonly.py", "--query", "all"])
    monkeypatch.setattr(probe, "collect", lambda: pytest.fail("unexpected read"))
    assert probe.main() == 2
    output = json.loads(capsys.readouterr().out)
    assert output["result"] == "NOTERI_HCS_READONLY_BLOCKED"


def test_hcs_api_error_does_not_print_sensitive_data(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["noteri_wsl_hcs_readonly.py"])
    monkeypatch.setattr(probe, "collect", lambda: (_ for _ in ()).throw(
        probe.Blocked("HCS_API_UNAVAILABLE")))
    assert probe.main() == 2
    assert "ubuntu_distro_running_verified" in capsys.readouterr().out


def test_safe_fixed_hcs_reason_is_reported_without_raw_exception(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["noteri_wsl_hcs_readonly.py"])
    monkeypatch.setattr(probe, "collect", lambda: (_ for _ in ()).throw(
        probe.Blocked("HCS_ENUMERATION_REJECTED")))
    assert probe.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "HCS_ENUMERATION_REJECTED"
    assert report["ubuntu_distro_running_verified"] is False


def test_arbitrary_hcs_error_is_never_echoed(monkeypatch, capsys):
    marker = "secret-GUID-private"
    monkeypatch.setattr(sys, "argv", ["noteri_wsl_hcs_readonly.py"])
    monkeypatch.setattr(probe, "collect", lambda: (_ for _ in ()).throw(
        probe.Blocked(marker)))
    assert probe.main() == 2
    result = capsys.readouterr().out
    assert marker not in result
    assert json.loads(result)["reason"] == "HCS_UNEXPECTED_FAILURE"


def test_vm_owner_must_explicitly_indicate_wsl():
    assert collect([dict(WSL_VM, Owner="windows")])["wsl_vm_candidate_observed"] is False
