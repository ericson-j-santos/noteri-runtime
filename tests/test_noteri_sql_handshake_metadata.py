"""Offline deterministic tests: never connect to a real SQL Server."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

src = Path(__file__).with_name("noteri_sql_handshake_metadata.py")

class StubError(ValueError):
    pass

native = types.ModuleType("noteri_native_qualification")
native.Blocked = StubError
native.source_head = lambda sha: sha
native.profile = lambda: {"profile": "NORMAL", "verified": True}
native.sql_inventory = lambda: {"status": "observed", "instances": [
    {"instance": "MSSQLSERVER", "installed_version": "17.0.1000.7", "service_state": "running"}]}
network = types.ModuleType("noteri_sql_network_inventory")
network.Blocked = StubError
network.INSTANCE_INDEX = r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
network.INSTANCE_ROOT = r"SOFTWARE\Microsoft\Microsoft SQL Server"
network.read_network = lambda reg: {
    "tcp_enabled": True, "tcp_listen_port_configured_ipall": True,
    "tcp_dynamic_port_configured_ipall": False, "force_encryption": False,
}
tcp = types.ModuleType("noteri_sql_local_tcp_probe")
tcp.Blocked = StubError
tcp.configured_port = lambda reg: 1433
with patch.dict(sys.modules, {
    "noteri_native_qualification": native,
    "noteri_sql_network_inventory": network,
    "noteri_sql_local_tcp_probe": tcp,
}):
    spec = importlib.util.spec_from_file_location("sqlcerttest", src)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)


class Key:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class Registry:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    thumb = "a" * 40

    def __init__(self, binding=None, store=False, instance="MSSQL17.MSSQLSERVER"):
        self.calls = []
        base = network.INSTANCE_ROOT + "\\" + "MSSQL17.MSSQLSERVER" + r"\MSSQLServer\SuperSocketNetLib"
        self.data = {
            network.INSTANCE_INDEX.casefold(): {"MSSQLSERVER": instance},
            base.casefold(): {"Certificate": binding} if binding is not None else {},
        }
        if store:
            self.data[(m.STORE_ROOT + "\\" + (binding or self.thumb)).casefold()] = {}

    def OpenKey(self, hive, path, zero, access):
        assert hive == self.HKEY_LOCAL_MACHINE
        assert zero == 0 and access == self.KEY_READ | self.KEY_WOW64_64KEY
        self.calls.append(("OpenKey", path))
        if path.casefold() not in self.data:
            raise FileNotFoundError
        return Key(self.data[path.casefold()])

    def QueryValueEx(self, key, name):
        self.calls.append(("QueryValueEx", name))
        if name not in key.data:
            raise FileNotFoundError
        return key.data[name], 1


def reply(mode=1):
    payload = m.PRELOGIN_BODY[:-1] + bytes([mode])
    length = 8 + len(payload)
    return b"\x04\x01" + length.to_bytes(2, "big") + b"\x00\x00\x01\x00" + payload


class Socket:
    def __init__(self, data):
        self.data = data
        self.writes = []
        self.closed = False
        self.timeout = None

    def settimeout(self, seconds):
        self.timeout = seconds

    def sendall(self, data):
        self.writes.append(data)

    def recv(self, count):
        data = self.data[:min(count, 3)]  # Force fragmented reads
        self.data = self.data[len(data):]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


def sock(reply_bytes):
    sockets = []
    def dial(address, timeout):
        assert address == ("127.0.0.1", 1433)
        assert timeout == 3.0
        x = Socket(reply_bytes)
        sockets.append(x)
        return x
    return dial, sockets


def test_no_explicit_binding_is_not_claimed_as_self_signed():
    r = Registry()
    d = m.certificate_binding(r)
    assert d == {
        "certificate_binding": "not_explicitly_configured",
        "configured_thumbprint_in_local_machine_my": None,
        "automatic_certificate_selection_unverified": True,
    }
    assert not any("Blob" in str(c) for c in r.calls)


@pytest.mark.parametrize("store,expected", [
    (True, "explicit_store_entry_present"),
    (False, "explicit_store_entry_absent"),
])
def test_thumbprint_presence_only_not_identity_or_validity(store, expected):
    r = Registry(binding="a" * 40, store=store)
    result = m.certificate_binding(r)
    assert result["certificate_binding"] == expected
    assert result["configured_thumbprint_in_local_machine_my"] is store
    assert "a" * 40 not in json.dumps(result)
    assert [name for action, name in r.calls if action == "QueryValueEx"] == [
        "MSSQLSERVER", "Certificate"
    ]


@pytest.mark.parametrize("binding", ["not-hex", "b" * 39, "x" * 40,
                                         "\u200eb" * 20, b"binary-value"])
def test_invalid_thumbprints_fail_closed_without_leak(binding):
    with pytest.raises(m.Blocked, match="certificate_binding_format_invalid"):
        m.certificate_binding(Registry(binding=binding))


def test_unexpected_sql_instance_fails_before_cert_lookup():
    r = Registry(instance="MSSQL17.DEV")
    with pytest.raises(m.Blocked, match="sql2025_registry_instance_unverified"):
        m.certificate_binding(r)
    assert [name for action, name in r.calls if action == "QueryValueEx"] == ["MSSQLSERVER"]


@pytest.mark.parametrize("mode,label,encrypt", [
    (0, "off", False), (1, "on", True), (2, "not_supported", False), (3, "required", True)
])
def test_prelogin_encryption_modes(mode, label, encrypt):
    dial, opened = sock(reply(mode))
    result = m.tds_prelogin(dial)
    assert result["tds_prelogin_response_valid"] is True
    assert result["tds_server_encryption_mode"] == label
    assert result["tds_encryption_negotiated"] is encrypt
    assert opened[0].writes == [m.PRELOGIN_PACKET]
    assert opened[0].closed
    assert opened[0].timeout == 3.0
    assert m.PRELOGIN_PACKET[0] == 0x12
    assert m.PRELOGIN_PACKET[-1] == 1  # ENCRYPT_ON
    assert b"SELECT" not in m.PRELOGIN_PACKET


def test_invalid_or_absent_tds_returns_unverified():
    for malformed in (b"", b"\x00" * 8, b"\x04\x01\x00\x09\x00\x00\x01\x00\xff",
                      b"\x04\x01\x20\x00\x00\x00\x01\x00"):
        dial, opened = sock(malformed)
        result = m.tds_prelogin(dial)
        assert result["tds_prelogin_response_valid"] is False
        assert result["tds_prelogin_status"] == "unavailable_or_invalid_response"
        assert opened[0].closed


def test_malformed_encryption_response_does_not_get_true():
    data = bytearray(m.PRELOGIN_BODY)
    data[-1] = 255
    with pytest.raises(m.ProtocolUnverified, match="prelogin_encryption_value_invalid"):
        m.parse_prelogin_response(bytes(data))
    data = bytearray(m.PRELOGIN_BODY)
    data[6:8] = b"\xff\xfe"
    with pytest.raises(m.ProtocolUnverified, match="prelogin_encryption_offset_invalid"):
        m.parse_prelogin_response(bytes(data))


def test_successful_read_only_collection_and_replay():
    r = Registry(binding="A" * 40, store=True)
    dial, _ = sock(reply(1))
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"):
        result = m.collect("a" * 40, "rbsql-cert-20261025", r, dial)
    assert result["status"] == "observed"
    assert result["tds_prelogin_response_valid"] is True
    assert result["certificate_binding"] == "explicit_store_entry_present"
    for f in ("tls_certificate_chain_verified", "tls_certificate_hostname_verified",
              "sql_connection_authenticated", "report_builder_sql_preflight_passed",
              "registry_modified", "production_touched", "business_rows_read",
              "server_certificate_effective_identity_verified"):
        assert result[f] is False
    dial2, _ = sock(reply(1))
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"):
        assert result == m.collect("a" * 40, "rbsql-cert-20261025", Registry(binding="A" * 40, store=True), dial2)


def test_host_and_profile_block_before_registry_and_dial():
    r = Registry()
    def no_connect(*_a, **_k):
        pytest.fail("unexpected socket")
    with pytest.raises(m.Blocked, match="noteri_windows_required"):
        m.collect("a" * 40, "rbsql-cert-20261025", r, no_connect)
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"):
        with pytest.raises(m.Blocked, match="source_sha_invalid"):
            m.collect("bad", "rbsql-cert-20261025", r, no_connect)
        with patch.object(native, "profile", return_value={"profile": "ESTUDO", "verified": True}):
            with pytest.raises(m.Blocked, match="normal_profile_required"):
                m.collect("a" * 40, "rbsql-cert-20261025", r, no_connect)
    assert not r.calls


def test_mismatched_source_rejected_before_reading_registry():
    r = Registry()
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(native, "source_head", side_effect=StubError("source_sha_mismatch")):
        with pytest.raises(StubError, match="source_sha_mismatch"):
            m.collect("a" * 40, "rbsql-cert-20261025", r, lambda *_a, **_k: None)
    assert not r.calls


def test_source_contains_no_admin_mutations_or_degraded_tls():
    data = src.read_text()
    for forbidden in ("SetValueEx", "SetValue", "CREATE DATABASE", "ALTER LOGIN",
                      "TrustServerCertificate=Yes", "Encrypt=No", "shell=True",
                      "sqlcmd", "os.system(", "powershell", "wsl.exe", "CertOpenStore"):
        assert forbidden not in data
    assert "sock.sendall(PRELOGIN_PACKET)" in data
    assert "STORE_ROOT" in data
    assert "QueryValueEx" in data
