"""Testes sem Windows real do inventario do Python S4U."""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "noteri_watchdog_python_compat_readonly.py"
spec = importlib.util.spec_from_file_location("noteri_watchdog_python_compat_readonly", SCRIPT)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def xml(command):
    return (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Actions><Exec><Command>' + command + '</Command></Exec></Actions></Task>'
    )


def test_windows_task_interpreter_path_and_reject_unknown_commands():
    assert m.task_command(xml(r"C:\Python312\python.exe")) == r"C:\Python312\python.exe"
    assert m.task_command(xml(r'"C:\Program Files\Python\python3.exe"')) == r"C:\Program Files\Python\python3.exe"
    for exe in (r"C:\Windows\System32\cmd.exe", r"C:\Temp\powershell.exe", "pythonw.exe"):
        with pytest.raises(m.Blocked, match="TASK_PYTHON_UNEXPECTED"):
            m.task_command(xml(exe))


def test_task_xml_extra_action_and_malformed_fail_closed():
    extra = xml("python.exe").replace(
        "</Actions>", "<Exec><Command>python.exe</Command></Exec></Actions>"
    )
    with pytest.raises(m.Blocked, match="TASK_ACTION_INVALID"):
        m.task_command(extra)
    with pytest.raises(m.Blocked, match="TASK_XML_INVALID"):
        m.task_command("<Task")


def test_pywin32_import_positive_and_negative(monkeypatch):
    seen = []
    def good(name):
        seen.append(name)
        return types.SimpleNamespace()
    monkeypatch.setattr(m.importlib, "import_module", good)
    assert m.importable() is True
    assert seen == ["win32com.client", "pythoncom"]

    def bad(name):
        raise ImportError("C:/Private/Location")
    monkeypatch.setattr(m.importlib, "import_module", bad)
    assert m.importable() is False


def test_child_checks_expected_source_and_executable_hash(monkeypatch, capsys):
    monkeypatch.setattr(m, "sha256", lambda path: "a" * 64)
    with pytest.raises(m.Blocked, match="CHILD_HASH_MISMATCH"):
        m.child("a" * 64, "b" * 64)
    assert not capsys.readouterr().out


def test_source_no_install_or_unrestricted_shell():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shell=False" in source
    assert '"-I", "-B"' in source
    assert '"/Query", "/TN", watchdog.TASK_NAME, "/XML"' in source
    assert '"installation_authorized": False' in source
    assert '"state_changed": False' in source
    for forbidden in ("pip install", "RegisterTask(", "RegisterTaskDefinition(", "DeleteTask("):
        assert forbidden not in source


def test_fixed_upgrade_preflight_command_is_readonly(monkeypatch, tmp_path):
    import json
    exe = tmp_path / "python.exe"
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    exe.write_bytes(b"python")
    (script_dir / "noteri_watchdog_transactional_upgrade.py").write_bytes(b"upgrade")
    (script_dir / "noteri_control_plane_watchdog.py").write_bytes(b"watchdog")
    expected_binary = m.sha256(exe)
    observed = []
    class Completed:
        returncode = 0
        stdout = json.dumps({"result": "PREFLIGHT_OK_NOT_AUTHORIZED",
                             "state_changed": False, "target_sha": "a"*40, "old_sha": m.OLD_SHA})
    def fake_run(args, **kwargs):
        observed.append((args,kwargs))
        return Completed()
    monkeypatch.setattr(m.subprocess, "run", fake_run)
    result = m.upgrade_preflight_using_task_python(
        tmp_path, exe, expected_binary, "a"*40, "read-only-1234", {}
    )
    assert result == "PREFLIGHT_OK_NOT_AUTHORIZED"
    args, kwargs = observed[0]
    assert args[0] == str(exe)
    assert "--mode" in args and args[args.index("--mode")+1] == "preflight"
    assert "upgrade" not in (args[args.index("--mode")+1],)
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 35


def test_fixed_upgrade_preflight_rejects_mutated_result(monkeypatch, tmp_path):
    import json
    exe = tmp_path / "python.exe"
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    exe.write_bytes(b"python")
    (scripts / "noteri_watchdog_transactional_upgrade.py").write_bytes(b"upgrade")
    (scripts / "noteri_control_plane_watchdog.py").write_bytes(b"watchdog")
    class Completed:
        returncode = 0
        stdout = json.dumps({"result": "PREFLIGHT_OK_NOT_AUTHORIZED", "state_changed": True,
                             "target_sha": "a"*40, "old_sha": m.OLD_SHA})
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: Completed())
    with pytest.raises(m.Blocked, match="UPGRADE_PREFLIGHT_RESPONSE_INVALID"):
        m.upgrade_preflight_using_task_python(tmp_path, exe, m.sha256(exe), "a"*40, "test-1234", {})
