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
