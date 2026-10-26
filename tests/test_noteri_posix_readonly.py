"""Contract and denial tests; no Windows, WSL or database process is launched."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "noteri_posix_readonly.py"
spec = importlib.util.spec_from_file_location("noteri_posix_readonly", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

FILES = {
    "/proc/sys/kernel/osrelease": "6.6.87.2-microsoft-standard-WSL2\n",
    "/etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n',
    "/proc/1/comm": "systemd\n",
}
RETURNS = {
    "systemd": (0, "running\n"),
    "psql": (0, "psql (PostgreSQL) 18.1\n"),
    "postgresql_service": (0, "active\n"),
}


class ReadOnly:
    def __init__(self, files=None, results=None):
        self.files = dict(FILES if files is None else files)
        self.results = dict(RETURNS if results is None else results)
        self.calls = []
        self.reads = []

    def read(self, path):
        self.reads.append(path)
        return self.files[path]

    def run(self, argv, **kw):
        self.calls.append((tuple(argv), kw))
        assert kw == {
            "shell": False, "check": False, "capture_output": True,
            "text": True, "timeout": 5, "cwd": "/", "close_fds": True,
            "env": {"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        }
        matching = [name for name, fixed in probe.PROBE_COMMANDS if fixed == tuple(argv)]
        assert len(matching) == 1
        code, output = self.results[matching[0]]
        return SimpleNamespace(returncode=code, stdout=output, stderr="NEVER_EXPOSE_THIS")


def measure(fake, **overrides):
    return probe.collect(
        platform_name=overrides.get("platform_name", "linux"),
        hostname=overrides.get("hostname", "Noteri"),
        distro_name=overrides.get("distro_name", "Ubuntu-24.04"),
        read_text=fake.read,
        run_command=fake.run,
    )


def test_positive_observation_is_not_database_or_agent_readiness():
    io = ReadOnly()
    result = measure(io)
    assert result["wsl2_ubuntu_observed"] is True
    assert result["systemd_pid1"] is True
    assert result["systemd_state"] == "running"
    assert result["psql_client_present"] is True and result["psql_major"] == 18
    assert result["postgresql_service_active"] is True
    assert result["postgresql_connection_verified"] is False
    assert result["gateway_session_verified"] is False
    assert result["distro_previously_running_verified"] is False
    assert result["agent_qwen_autonomous_verified"] is False
    assert result["ready_for_postgresql"] is False
    assert [item[0] for item in io.calls] == [p[1] for p in probe.PROBE_COMMANDS]


@pytest.mark.parametrize(("override", "value"), [
    ("platform_name", "win32"), ("hostname", "OtherHost"),
    ("distro_name", "Debian"), ("distro_name", "Ubuntu;bash"),
    ("distro_name", "Ubuntu-24.04 --exec sh"),
])
def test_wrong_identity_blocks_before_running_any_command(override, value):
    io = ReadOnly()
    with pytest.raises(probe.Blocked):
        measure(io, **{override: value})
    assert io.calls == []


@pytest.mark.parametrize(("path", "bad"), [
    ("/proc/sys/kernel/osrelease", "Linux 6.6.0 generic"),
    ("/proc/sys/kernel/osrelease", "4.19.128-microsoft-standard"),
    ("/etc/os-release", "ID=debian\n"),
    ("/etc/os-release", "ID=ubuntu\nID=ubuntu\n"),
])
def test_not_ubuntu_wsl2_denied_without_command(path, bad):
    files = dict(FILES, **{path: bad})
    io = ReadOnly(files=files)
    with pytest.raises(probe.Blocked):
        measure(io)
    assert io.calls == []


def test_systemd_not_pid1_skips_systemctl_but_checks_psql_version():
    io = ReadOnly(files=dict(FILES, **{"/proc/1/comm": "init\n"}))
    result = measure(io)
    assert result["systemd_pid1"] is False
    assert result["postgresql_service_state"] == "unavailable"
    assert result["systemd_state"] == "unavailable"
    assert [c[0] for c in io.calls] == [("/usr/bin/psql", "--version")]


def test_degraded_systemd_does_not_mark_inactive_service_active():
    io = ReadOnly(results={
        "systemd": (1, "degraded\n"), "psql": (0, "psql (PostgreSQL) 15.6\n"),
        "postgresql_service": (3, "inactive\n"),
    })
    result = measure(io)
    assert result["systemd_state"] == "degraded"
    assert result["psql_major"] == 15
    assert result["postgresql_service_state"] == "inactive"
    assert result["postgresql_service_active"] is False


def test_unexpected_output_is_sanitized_and_not_false_positive():
    marker = "TOKEN_SECRET_VALUE_DONOTLEAK"
    io = ReadOnly(results={
        "systemd": (0, marker), "psql": (0, marker),
        "postgresql_service": (0, marker),
    })
    result = measure(io)
    assert marker not in json.dumps(result)
    assert result["systemd_state"] == "unknown"
    assert result["postgresql_service_state"] == "unknown"
    assert result["psql_client_present"] is False
    assert result["ready_for_postgresql"] is False


@pytest.mark.parametrize("error", [OSError("sensitive path"), subprocess.TimeoutExpired("probe", 5)])
def test_runtime_failure_blocks_without_leaking(error):
    io = ReadOnly()
    def fail(*_args, **_kwargs):
        raise error
    with pytest.raises(probe.Blocked) as exc:
        probe.collect(platform_name="linux", hostname="noteri", distro_name="Ubuntu",
                      read_text=io.read, run_command=fail)
    assert "sensitive" not in str(exc.value)


def test_excessive_output_blocks():
    io = ReadOnly(results=dict(RETURNS, systemd=(0, "x"*513)))
    with pytest.raises(probe.Blocked, match="PROBE_OUTPUT_LIMIT"):
        measure(io)


def test_repeat_has_identical_output_and_only_same_fixed_read_operations():
    io = ReadOnly()
    first = measure(io)
    second = measure(io)
    assert first == second
    assert io.reads == list(probe.READ_PATHS) * 2
    assert [c[0] for c in io.calls] == [p[1] for p in probe.PROBE_COMMANDS] * 2
    assert all(r.get("ready_for_postgresql") is False for r in (first, second))


def test_no_arbitrary_probe_names_accepted():
    io = ReadOnly()
    with pytest.raises(probe.Blocked, match="PROBE_NOT_ALLOWED"):
        probe._fixed_probe("bash", io.run)
    assert not io.calls


def test_os_file_read_is_bounded_and_only_fixed_paths(monkeypatch):
    with pytest.raises(probe.Blocked, match="PATH_DENIED"):
        probe._read_fixed("/etc/shadow")


def test_cli_arguments_are_rejected_before_probe(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["noteri_posix_readonly.py", "--command", "sh"])
    monkeypatch.setattr(probe, "collect", lambda: pytest.fail("executed"))
    assert probe.main() == 2
    assert json.loads(capsys.readouterr().out)["result"] == "NOTERI_POSIX_PASSIVE_BLOCKED"


def test_fixed_command_whitelist_and_no_wsl_start_or_sensitive_ops():
    assert probe.PROBE_COMMANDS == (
        ("systemd", ("/usr/bin/systemctl", "is-system-running")),
        ("psql", ("/usr/bin/psql", "--version")),
        ("postgresql_service", ("/usr/bin/systemctl", "is-active", "postgresql.service")),
    )
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ["shell=True", "wsl.exe", "sudo ", "systemctl start",
                      "systemctl restart", "pg_ctl", "psql -c", "CREATE DATABASE",
                      "subprocess.Popen", "os.system(", "eval(", "exec("]:
        assert forbidden not in source
