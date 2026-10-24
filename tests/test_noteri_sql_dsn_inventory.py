"""Read-only ODBC DSN registry discovery contracts; no SQL/network side effects."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SOURCE = ROOT / "scripts" / "noteri_sql_dsn_inventory.py"
spec = importlib.util.spec_from_file_location("noteri_dsn_inventory", SOURCE)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

DEV = {
    "Server": "localhost",
    "Database": "ReqSysDev",
    "Trusted_Connection": "Yes",
    "Encrypt": "Yes",
    "TrustServerCertificate": "No",
}
DRIVER = "ODBC Driver 18 for SQL Server"


class Key:
    def __init__(self, kind, records, name=None):
        self.kind = kind
        self.records = records
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class FakeRegistry:
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200

    def __init__(self, entries=None):
        self.entries = entries or {}
        self.queried_fields = []
        self.opened_paths = []

    def OpenKey(self, hive, path, unused=0, flags=0):
        self.opened_paths.append(path)
        view = flags & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        rows = self.entries.get((hive, view), [])
        if not rows:
            raise FileNotFoundError
        if path == m.DATA_SOURCE_ROOT + r"\ODBC Data Sources":
            return Key("sources", rows)
        prefix = m.DATA_SOURCE_ROOT + "\\"
        if not path.startswith(prefix):
            raise AssertionError("unexpected_registry_path")
        name = path[len(prefix):]
        matches = [x for x in rows if x[0] == name]
        if len(matches) != 1:
            raise FileNotFoundError
        return Key("values", matches, name)

    def QueryInfoKey(self, key):
        assert key.kind == "sources"
        return 0, len(key.records), 0

    def EnumValue(self, key, index):
        assert key.kind == "sources"
        name, driver, _ = key.records[index]
        return name, driver, 1

    def QueryValueEx(self, key, field):
        assert key.kind == "values"
        assert field in m.REGISTRY_FIELDS, "sensitive_field_requested"
        self.queried_fields.append(field)
        fields = key.records[0][2]
        if field not in fields:
            raise FileNotFoundError
        return fields[field], 1


def view(rows, *, scope="HKLM", flag=FakeRegistry.KEY_WOW64_64KEY):
    return FakeRegistry({(scope, flag): rows})


def test_positive_local_dev_candidate_is_only_metadata():
    result = m.inventory(view([("ReqSysDev", DRIVER, DEV)]))
    assert result["status"] == "observed"
    assert result["sql_server_dsn_entries"] == 1
    assert result["local_dev_metadata_entries"] == 1
    assert result["strict_tls_integrated_candidates"] == 1
    assert result["unambiguous_strict_candidate"] is True
    for key in (
        "dsn_value_exported", "credential_value_read", "sql_connection_tested",
        "sql_principal_readonly_verified", "database_identity_verified",
        "fabric_gateway_identity_verified", "registry_modified",
        "hml_verified", "production_touched",
    ):
        assert result[key] is False
    serialized = json.dumps(result)
    for sensitive in ("ReqSysDev", "localhost", "Trusted_Connection", "Password"):
        assert sensitive not in serialized


@pytest.mark.parametrize("name,driver,values", [
    ("ReqSysProd", DRIVER, DEV),
    ("ReqSysDev", DRIVER, {**DEV, "Database": "ReqSysProd"}),
    ("ReqSysDev", DRIVER, {**DEV, "Database": "master"}),
    ("ReqSysDev", DRIVER, {**DEV, "Server": "remote.company.internal"}),
    ("ReqSysDev", DRIVER, {**DEV, "Server": "localhost,1433"}),
    ("ReqSysDev", "ODBC Driver 17 for SQL Server", DEV),
    ("ReqSysDev", DRIVER, {**DEV, "Trusted_Connection": "No"}),
    ("ReqSysDev", DRIVER, {**DEV, "Encrypt": "No"}),
    ("ReqSysDev", DRIVER, {**DEV, "TrustServerCertificate": "Yes"}),
    ("ReqSysDev", DRIVER, {k: v for k, v in DEV.items() if k != "Database"}),
    ("ReqSysDev", DRIVER, {k: v for k, v in DEV.items() if k != "Encrypt"}),
])
def test_reject_unsafe_target_or_tls(name, driver, values):
    r = m.inventory(view([(name, driver, values)]))
    assert r["unambiguous_strict_candidate"] is False
    assert r["strict_tls_integrated_candidates"] == 0


def test_two_candidates_are_ambiguous():
    r = m.inventory(view([
        ("ReqSysDev", DRIVER, DEV),
        ("ReportingDev", DRIVER, {**DEV, "Database": "ReportsDev"}),
    ]))
    assert r["strict_tls_integrated_candidates"] == 2
    assert r["unambiguous_strict_candidate"] is False


def test_empty_registry_says_no_candidate():
    r = m.inventory(FakeRegistry())
    assert r["status"] == "observed"
    assert r["sql_server_dsn_entries"] == 0
    assert r["strict_tls_integrated_candidates"] == 0


def test_registry_reads_only_whitelisted_nonsecret_values():
    registry = view([("ReqSysDev", DRIVER, {**DEV, "PWD": "do-not-read"})])
    r = m.inventory(registry)
    assert r["status"] == "observed"
    assert set(registry.queried_fields) == set(m.REGISTRY_FIELDS)
    assert "PWD" not in registry.queried_fields
    assert "do-not-read" not in json.dumps(r)


def test_conflicting_32_and_64_bit_entries_fail_closed():
    reg = FakeRegistry({
        ("HKLM", FakeRegistry.KEY_WOW64_64KEY): [("ReqSysDev", DRIVER, DEV)],
        ("HKLM", FakeRegistry.KEY_WOW64_32KEY): [
            ("ReqSysDev", DRIVER, {**DEV, "Database": "DifferentDev"})
        ],
    })
    with pytest.raises(m.Blocked, match="dsn_registry_view_conflict"):
        m.inventory(reg)


def test_duplicate_mirrored_view_is_deduplicated():
    reg = FakeRegistry({
        ("HKLM", FakeRegistry.KEY_WOW64_64KEY): [("ReqSysDev", DRIVER, DEV)],
        ("HKLM", FakeRegistry.KEY_WOW64_32KEY): [("ReqSysDev", DRIVER, DEV)],
    })
    r = m.inventory(reg)
    assert r["data_source_registry_entries"] == 2
    assert r["sql_server_dsn_entries"] == 1


@pytest.mark.parametrize("invalid_name", ["../ProdDev", r"Remote\Dev", "", "x" * 65])
def test_malformed_dsn_names_fail_closed(invalid_name):
    with pytest.raises(m.Blocked, match="dsn_name_shape_invalid"):
        m.inventory(view([(invalid_name, DRIVER, DEV)]))


def test_disallow_unapproved_registry_fields():
    reg = view([("ReqSysDev", DRIVER, DEV)])
    with pytest.raises(m.Blocked, match="registry_field_not_allowlisted"):
        m._optional_value(reg, object(), "PWD")


def test_source_not_validated_never_reads_registry():
    with patch.object(m.os, "name", "posix"), \
         patch.object(m.native, "source_head") as source, \
         patch.object(m.native, "profile") as profile:
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.observe("a" * 40, "sql-readiness-20261024")
        source.assert_not_called()
        profile.assert_not_called()


def test_cli_returns_sanitized_failure(capsys):
    result = m.main(["--expected-sha", "main", "--correlation-id", "bad"])
    assert result == 2
    value = json.loads(capsys.readouterr().out)
    assert value["status"] == "blocked"
    assert value["sql_connection_tested"] is False


def test_script_has_no_registry_write_or_secret_lookup():
    code = SOURCE.read_text(encoding="utf-8")
    for prohibited in ("SetValueEx", "CreateKey(", "DeleteKey(", "DeleteValue(",
                       "os.system(", "shell=True", "pyodbc.connect(",
                       '"PWD"', '"Password"', "SQLExecDirect"):
        assert prohibited not in code
