"""Offline negative and positive tests for Noteri's fixed local SQL metadata query."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SOURCE = ROOT / "scripts" / "noteri_sql_dev_metadata_locator.py"
spec = importlib.util.spec_from_file_location("noteri_dev_locator", SOURCE)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Cursor:
    def __init__(self, server="Noteri", db="master", sysadmin=0, names=None):
        self.identity = (server, db, sysadmin)
        self.names = ["ReqSysDev", "OtherProd"] if names is None else names
        self.statements = []
        self.closed = False

    def execute(self, sql):
        self.statements.append(sql)

    def fetchone(self):
        assert self.statements[-1] == m.IDENTITY_SQL
        return self.identity

    def fetchall(self):
        assert self.statements[-1] == m.CATALOG_SQL
        return [(name,) for name in self.names]

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, **kwargs):
        self.cur = Cursor(**kwargs)
        self.closed = False

    def cursor(self):
        return self.cur

    def close(self):
        self.closed = True


def test_metadata_positive_reveals_no_target_names():
    db = Connection()
    data = m.inspect_connection(db)
    assert data["status"] == "observed"
    assert data["visible_dev_database_candidates"] == 1
    assert data["unique_visible_dev_database"] is True
    assert data["sql_connection_tested"] is True
    for key in ("database_identity_verified", "sql_principal_readonly_verified",
                "report_builder_sql_preflight_passed", "fabric_gateway_identity_verified",
                "production_touched", "data_mutations_performed", "business_rows_read"):
        assert data[key] is False
    assert db.cur.statements == [m.IDENTITY_SQL, m.CATALOG_SQL]
    assert db.cur.closed
    encoded = json.dumps(data)
    assert "ReqSysDev" not in encoded and "OtherProd" not in encoded


@pytest.mark.parametrize("server,db,admin,error", [
    ("Other", "master", 0, "local_instance_identity_mismatch"),
    ("Noteri", "ReqSysDev", 0, "metadata_database_mismatch"),
    ("Noteri", "master", 1, "integrated_identity_not_restricted"),
    ("Noteri", "master", None, "integrated_identity_not_restricted"),
])
def test_identity_or_privilege_blocks_before_catalog(server, db, admin, error):
    con = Connection(server=server, db=db, sysadmin=admin)
    with pytest.raises(m.Blocked, match=error):
        m.inspect_connection(con)
    assert con.cur.statements == [m.IDENTITY_SQL]
    assert con.cur.closed


@pytest.mark.parametrize("names", [
    ["SysDev", "AppDev"],
    [],
    ["Data HML"],
])
def test_zero_or_ambiguous_dev_database_is_not_unique(names):
    result = m.inspect_connection(Connection(names=names))
    assert result["unique_visible_dev_database"] == (len([n for n in names
                                                         if m._has_dev_segment(n)]) == 1)


def test_invalid_catalog_row_rejected_and_cursor_closed():
    c = Connection(names=["Bad\\Name"])
    with pytest.raises(m.Blocked, match="catalog_entry_invalid"):
        m.inspect_connection(c)
    assert c.cur.closed


def test_query_inventory_is_fixed_read_only_and_tls_strict():
    assert m.IDENTITY_SQL.startswith("SELECT ")
    assert m.CATALOG_SQL.startswith("SELECT ")
    for statement in (m.IDENTITY_SQL, m.CATALOG_SQL):
        assert not re.search(r"\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|EXEC)\b",
                             statement, re.IGNORECASE)
    assert "SERVER=localhost" in m.ODBC_LOCAL
    assert "DATABASE=master" in m.ODBC_LOCAL
    assert "Trusted_Connection=Yes" in m.ODBC_LOCAL
    assert "Encrypt=Yes" in m.ODBC_LOCAL
    assert "TrustServerCertificate=No" in m.ODBC_LOCAL
    assert "UID=" not in m.ODBC_LOCAL and "PWD=" not in m.ODBC_LOCAL


def test_untrusted_machine_is_blocked_before_any_db_calls():
    with patch.object(m.os, "name", "posix"), \
         patch.object(m.native, "source_head") as git, \
         patch.object(m.native, "sql_inventory") as inventory:
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.collect("a" * 40, "noteri-dev-metadata-2026", lambda *_a, **_kw: None)
        git.assert_not_called()
        inventory.assert_not_called()


def test_no_os_mutation_or_dynamic_sql_in_source():
    code = SOURCE.read_text(encoding="utf-8")
    for bad in ("shell=True", "os.system(", "StartServiceW", "SetValueEx",
                "CREATE DATABASE", "ALTER LOGIN", "TrustServerCertificate=Yes"):
        assert bad not in code


def test_replay_deterministic():
    left = m.inspect_connection(Connection())
    right = m.inspect_connection(Connection())
    assert left == right


@pytest.mark.parametrize("state,details,expected", [
    ("08001", "SSL Provider: certificate chain not trusted", "tls_certificate_validation_failed"),
    ("08001", "cadeia de certificados inválida", "tls_certificate_validation_failed"),
    ("28000", "Login failed user=private", "integrated_authentication_rejected"),
    ("HYT00", "timeout to private-host", "sql_connection_timeout"),
    ("IM002", "data source absent", "odbc_driver_configuration_unavailable"),
    ("08S01", "connection unexpectedly closed", "sql_transport_or_tls_unavailable"),
    ("42000", "denied", "sql_metadata_permission_rejected"),
    ("XXXXX", "secret=not-for-logs", "odbc_error_unclassified"),
])
def test_driver_error_classification_is_sanitized(state, details, expected):
    class DriverError(Exception):
        pass
    error = DriverError(state, details)
    classification = m.classify_odbc_error(error)
    assert classification == expected
    assert details not in classification
    assert "private" not in classification


def test_guarded_connection_blocks_without_leaking_driver_diagnostics():
    def fake_connect(*_args, **_kwargs):
        raise RuntimeError("08001", "PWD=do-not-echo host=private")
    with pytest.raises(m.Blocked) as exc:
        m.guarded_connect(fake_connect, m.ODBC_LOCAL, timeout=5)
    assert str(exc.value) == "sql_transport_or_tls_unavailable"
    assert "do-not-echo" not in str(exc.value)


def test_guarded_connection_allows_successful_connect_without_mutation():
    sentinel = object()
    assert m.guarded_connect(lambda *_a, **_kw: sentinel, m.ODBC_LOCAL) is sentinel
