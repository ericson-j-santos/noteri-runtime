"""No SQL queries: local-only TCP listener and port metadata validation."""
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_local_tcp_probe.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("noteri_tcp_probe", SOURCE)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Key:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class Registry:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100

    def __init__(self, port="1433", dynamic=""):
        instance = r"MSSQL17.MSSQLSERVER"
        self.root = {
            m.network.INSTANCE_INDEX: {"MSSQLSERVER": instance},
            (m.network.INSTANCE_ROOT + "\\" + instance
             + r"\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"): {
                 "TcpPort": port, "TcpDynamicPorts": dynamic,
             },
        }

    def OpenKey(self, hive, path, zero, access):
        assert hive == self.HKEY_LOCAL_MACHINE
        assert access == (self.KEY_READ | self.KEY_WOW64_64KEY)
        if path not in self.root:
            raise FileNotFoundError
        return Key(self.root[path])

    def QueryValueEx(self, key, name):
        if name not in key.data:
            raise FileNotFoundError
        return key.data[name], 1


class Sock:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


META = {
    "tcp_enabled": True,
    "tcp_listen_port_configured_ipall": True,
    "tcp_dynamic_port_configured_ipall": False,
}


def test_valid_local_socket_proves_only_listener():
    sock = Sock()
    seen = []

    def dial(address, timeout):
        seen.append((address, timeout))
        return sock

    with patch.object(m.network, "read_network", return_value=META):
        result = m.check_listener(Registry(), dial)
    assert seen == [(("127.0.0.1", 1433), 2.0)]
    assert sock.closed
    assert result["tcp_loopback_listener_responded"] is True
    assert result["default_tcp_port_configured"] is True
    for field in ("sql_login_attempted", "sql_connection_tested",
                  "sql_permissions_verified", "tls_certificate_verified",
                  "database_identity_verified", "fabric_identity_verified",
                  "business_data_read", "registry_modified", "production_touched"):
        assert result[field] is False
    assert "1433" not in json.dumps(result)


def test_connection_refusal_does_not_claim_listener():
    with patch.object(m.network, "read_network", return_value=META):
        r = m.check_listener(Registry(), lambda *_a, **_k:
                             (_ for _ in ()).throw(ConnectionRefusedError()))
    assert r["status"] == "observed"
    assert r["tcp_loopback_listener_responded"] is False
    assert r["sql_connection_tested"] is False


@pytest.mark.parametrize("port,dynamic", [
    ("0", ""), ("65536", ""), ("123456", ""), ("foo", ""),
    ("1433,1555", ""), ("1433", "0"),
])
def test_disallow_invalid_or_ambiguous_ports(port, dynamic):
    with pytest.raises(m.Blocked):
        m.configured_port(Registry(port, dynamic))


def test_valid_explicit_nonstandard_port_is_not_default():
    with patch.object(m.network, "read_network", return_value=META):
        result = m.check_listener(Registry(port="1444"), lambda *_a, **_k: Sock())
    assert result["tcp_loopback_listener_responded"] is True
    assert result["default_tcp_port_configured"] is False


@pytest.mark.parametrize("changes", [
    {"tcp_enabled": False},
    {"tcp_enabled": None},
    {"tcp_listen_port_configured_ipall": False},
    {"tcp_dynamic_port_configured_ipall": True},
])
def test_registry_gate_prevents_socket_attempt(changes):
    attempted = []
    with patch.object(m.network, "read_network", return_value={**META, **changes}):
        with pytest.raises(m.Blocked):
            m.check_listener(Registry(), lambda *_a, **_k: attempted.append(True))
    assert not attempted


def test_non_noteri_or_untrusted_host_blocks_before_socket():
    with patch.object(m.os, "name", "posix"), \
         patch.object(m.native, "source_head") as checked:
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.collect("a" * 40, "noteri-tcp-test-2026", Registry(), lambda *_a, **_k: None)
        checked.assert_not_called()


def test_no_sql_or_registry_changes_in_source():
    script = SOURCE.read_text(encoding="utf-8")
    for pattern in ("pyodbc.connect(", "SetValueEx", "CreateKey(", "DeleteKey(",
                    "shell=True", "TrustServerCertificate=Yes", "SELECT ", "INSERT "):
        assert pattern not in script


def test_replay_same_probe_is_deterministic():
    with patch.object(m.network, "read_network", return_value=META):
        r1 = m.check_listener(Registry(), lambda *_a, **_k: Sock())
        r2 = m.check_listener(Registry(), lambda *_a, **_k: Sock())
    assert r1 == r2
