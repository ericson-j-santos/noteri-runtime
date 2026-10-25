"""Mocked native Windows SQL Server protocol registry controls. No host changes."""
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_network_inventory.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("noteri_sql_network", SOURCE)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Key:
    def __init__(self, row):
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class Registry:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100

    def __init__(self, tcp=1, pipes=0, shared=1, port="1433", forced=0):
        base = m.INSTANCE_ROOT + r"\MSSQL17.MSSQLSERVER\MSSQLServer\SuperSocketNetLib"
        self.rows = {
            m.INSTANCE_INDEX: {"MSSQLSERVER": "MSSQL17.MSSQLSERVER"},
            base: {"ForceEncryption": forced},
            base + r"\Tcp": {"Enabled": tcp},
            base + r"\Np": {"Enabled": pipes},
            base + r"\Sm": {"Enabled": shared},
            base + r"\Tcp\IPAll": {"TcpPort": port, "TcpDynamicPorts": ""},
        }
        self.calls = []

    def OpenKey(self, hive, path, zero, flags):
        assert hive == self.HKEY_LOCAL_MACHINE
        assert flags == self.KEY_READ | self.KEY_WOW64_64KEY
        self.calls.append(path)
        if path not in self.rows:
            raise FileNotFoundError
        return Key(self.rows[path])

    def QueryValueEx(self, key, field):
        assert field in {
            "MSSQLSERVER", "Enabled", "ListenOnAllIPs", "TcpPort",
            "TcpDynamicPorts", "ForceEncryption",
        }
        if field not in key.row:
            raise FileNotFoundError
        return key.row[field], 1


def test_tcp_online_metadata_is_not_database_ready():
    data = m.read_network(Registry())
    assert data["status"] == "observed"
    assert data["tcp_enabled"] is True
    assert data["tcp_listen_port_configured_ipall"] is True
    assert data["tcp_readiness_comprovable"] is True
    assert data["named_pipes_enabled"] is False
    assert data["shared_memory_enabled"] is True
    for field in ("database_connection_tested", "sql_permissions_verified",
                  "certificate_validated", "registry_modified", "production_touched"):
        assert data[field] is False
    serialized = json.dumps(data)
    assert "MSSQL17.MSSQLSERVER" not in serialized and "1433" not in serialized


def test_tcp_disabled_is_not_promoted_even_if_port_set():
    result = m.read_network(Registry(tcp=0))
    assert result["tcp_enabled"] is False
    assert result["tcp_readiness_comprovable"] is False


def test_no_configured_port_is_not_tcp_ready():
    result = m.read_network(Registry(port=""))
    assert result["tcp_listen_port_configured_ipall"] is False
    assert result["tcp_readiness_comprovable"] is False


def test_missing_instance_identity_fails_closed():
    reg = Registry()
    reg.rows[m.INSTANCE_INDEX]["MSSQLSERVER"] = "RemoteDB"
    with pytest.raises(m.Blocked, match="instance_registry_identity_invalid"):
        m.read_network(reg)


def test_registry_missing_protocol_is_unknown_not_enabled():
    reg = Registry()
    base = m.INSTANCE_ROOT + r"\MSSQL17.MSSQLSERVER\MSSQLServer\SuperSocketNetLib"
    del reg.rows[base + r"\Tcp"]
    value = m.read_network(reg)
    assert value["tcp_enabled"] is None
    assert value["tcp_readiness_comprovable"] is False


@pytest.mark.parametrize("invalid", ["host:1433", "x" * 65, 1433])
def test_invalid_port_metadata_fails_closed(invalid):
    with pytest.raises(m.Blocked, match="port_config_invalid"):
        m.read_network(Registry(port=invalid))


def test_invalid_enabled_value_fails_closed():
    with pytest.raises(m.Blocked, match="protocol_setting_invalid"):
        m.read_network(Registry(tcp=42))


def test_non_windows_blocks_without_looking_at_registry():
    with patch.object(m.os, "name", "posix"), \
         patch.object(m.native, "source_head") as git:
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.collect("a" * 40, "noteri-net-sql-check")
        git.assert_not_called()


def test_source_has_no_registry_write_or_network_connection():
    text = SOURCE.read_text(encoding="utf-8")
    for value in ("SetValueEx", "CreateKey(", "DeleteKey(", "pyodbc.connect(", "sqlcmd",
                  "shell=True", "TrustServerCertificate=Yes"):
        assert value not in text


def test_replay_is_deterministic():
    assert m.read_network(Registry()) == m.read_network(Registry())
