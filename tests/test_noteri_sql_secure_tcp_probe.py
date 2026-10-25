"""Contract and fail-closed controls for local ODBC 18 TLS diagnosis (no real SQL in CI)."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_secure_tcp_probe.py"
sys.path.insert(0, str(SOURCE.parent))
spec = importlib.util.spec_from_file_location("noteri_secure_tcp_probe", SOURCE)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def _listener():
    return {"default_tcp_port_configured": True,
            "tcp_loopback_listener_responded": True}


def test_odbc_configuration_loopback_only_and_tls_strict():
    line = m.ODBC_TCP
    assert "SERVER=tcp:127.0.0.1,1433;" in line
    assert "HostNameInCertificate=Noteri;" in line
    for required in ("Trusted_Connection=Yes", "Encrypt=Yes",
                     "TrustServerCertificate=No", "ApplicationIntent=ReadOnly",
                     "DATABASE=master", "ODBC Driver 18 for SQL Server"):
        assert required in line
    for forbidden in ("PWD=", "UID=", "TrustServerCertificate=Yes",
                      "Encrypt=No", "SERVER=0.0.0.0"):
        assert forbidden not in line


def test_positive_requires_live_odbc_then_metadata_only_and_closes_connection():
    class Connection:
        closed = False
        def close(self):
            self.closed = True
    connection = Connection()
    calls = []
    def connect(dsn, **kwargs):
        calls.append((dsn, kwargs))
        return connection
    meta = {"status": "observed", "visible_dev_database_candidates": 1,
            "unique_visible_dev_database": True,
            "database_identity_verified": False,
            "sql_principal_readonly_verified": False}
    with patch.object(m.tcp, "check_listener", return_value=_listener()), \
         patch.object(m.locator, "inspect_connection", return_value=meta) as inspect:
        result = m.diagnostic(object(), lambda *a: None, connect)
    assert len(calls) == 1 and calls[0] == (m.ODBC_TCP,
                                          {"timeout": 5, "autocommit": True})
    inspect.assert_called_once_with(connection)
    assert connection.closed
    assert result["tls_certificate_validated_by_odbc18"] is True
    assert result["sql_login_succeeded"] is True
    assert result["database_identity_verified"] is False
    assert result["sql_principal_readonly_verified"] is False
    assert result["visible_dev_database_candidates"] == 1
    assert "password" not in json.dumps(result).lower()


@pytest.mark.parametrize("listener,expected", [
    ({"default_tcp_port_configured": False, "tcp_loopback_listener_responded": True},
     "nonstandard_local_tcp_port_not_allowlisted"),
    ({"default_tcp_port_configured": True, "tcp_loopback_listener_responded": False},
     "local_tcp_listener_not_responding"),
])
def test_listener_unverified_does_not_attempt_sql(listener, expected):
    with patch.object(m.tcp, "check_listener", return_value=listener):
        def connect(*_a, **_k):
            pytest.fail("SQL attempted with unqualified listener")
        with pytest.raises(m.Blocked, match=expected):
            m.diagnostic(object(), lambda *_a: None, connect)


@pytest.mark.parametrize("state,detail,expected", [
    ("08001", "SSL Provider: The certificate chain was issued by an authority that is not trusted",
     "tls_certificate_trust_failure"),
    ("08001", "SSL Provider: The target principal name is incorrect (certificate)",
     "tls_certificate_name_mismatch"),
    ("08001", "SSL Provider certificate subject name does not match", "tls_certificate_name_mismatch"),
    ("08001", "certificate validation error", "tls_certificate_other_failure"),
    ("28000", r"Login failed for user domain\private", "integrated_authentication_rejected"),
    ("08001", "TCP Provider actively refused connection (10061)", "sql_tcp_connection_refused"),
    ("HYT00", "Login timeout expired", "sql_connection_timeout"),
    ("08S01", "SSL Provider: handshake error", "tls_negotiation_unclassified"),
    ("08S01", "Socket unexpectedly closed", "sql_transport_or_tls_unclassified"),
    ("IM002", "driver absent", "odbc_driver_configuration_unavailable"),
    ("XXXXX", "PRIVATE-SERVER;Password=SECRET", "odbc_error_unclassified"),
])
def test_odbc_failure_categories_sanitized(state, detail, expected):
    exc = RuntimeError(state, detail)
    code = m._safe_error(exc)
    assert code == expected
    assert detail not in code
    assert "SECRET" not in code


def test_negative_connection_error_sanitized_and_denies_sql_identity():
    def connect(*_args, **_kwargs):
        raise RuntimeError("08001", "PRIVATE=token;SSL Provider: The certificate chain is not trusted")
    with patch.object(m.tcp, "check_listener", return_value=_listener()):
        result = m.diagnostic(object(), lambda *_: None, connect)
    assert result["status"] == "blocked"
    assert result["code"] == "tls_certificate_trust_failure"
    for flag in ("sql_login_succeeded", "tls_certificate_validated",
                 "sql_principal_readonly_verified", "database_identity_verified",
                 "data_mutations_performed", "business_rows_read", "production_touched"):
        assert result[flag] is False
    assert "PRIVATE" not in json.dumps(result)


def test_metadata_rejected_does_not_leave_connection_open():
    class Connection:
        closed = False
        def close(self):
            self.closed = True
    connection = Connection()
    with patch.object(m.tcp, "check_listener", return_value=_listener()), \
         patch.object(m.locator, "inspect_connection",
                      side_effect=m.locator.Blocked("integrated_identity_not_restricted")):
        with pytest.raises(m.locator.Blocked, match="integrated_identity_not_restricted"):
            m.diagnostic(object(), lambda *_: None, lambda *_args, **_kw: connection)
    assert connection.closed


def test_replay_is_deterministic_and_still_has_no_sql_login():
    def connect(*_args, **_kwargs):
        raise RuntimeError("08S01", "transport closed")
    with patch.object(m.tcp, "check_listener", return_value=_listener()):
        assert m.diagnostic(object(), lambda *_: None, connect) == \
               m.diagnostic(object(), lambda *_: None, connect)


def test_host_and_invalid_sha_block_before_source_or_sql():
    with patch.object(m.os, "name", "posix"), \
         patch.object(m.native, "source_head") as git:
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.check_guard("a" * 40, "sql-20261025")
        git.assert_not_called()
    with patch.object(m.os, "name", "nt"), \
         patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m.native, "source_head") as git:
        with pytest.raises(m.Blocked, match="source_sha_invalid"):
            m.check_guard("bad", "sql-20261025")
        git.assert_not_called()


def test_guard_requires_normal_profile_and_driver():
    sql = {"status": "observed", "instances": [{"instance": "MSSQLSERVER",
           "installed_version": "17.0.1000.7", "service_state": "running"}],
           "odbc_drivers": ["ODBC Driver 18 for SQL Server"]}
    with patch.object(m.os, "name", "nt"), \
         patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m.native, "source_head") as git, \
         patch.object(m.native, "profile", return_value={"verified": True, "profile": "NORMAL"}), \
         patch.object(m.native, "sql_inventory", return_value=sql):
        m.check_guard("a" * 40, "noteri-sql-20261025")
        git.assert_called_once_with("a" * 40)
    with patch.object(m.os, "name", "nt"), \
         patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m.native, "source_head"), \
         patch.object(m.native, "profile", return_value={"verified": True, "profile": "ESTUDO"}):
        with pytest.raises(m.Blocked, match="normal_profile_required"):
            m.check_guard("a" * 40, "noteri-sql-20261025")


def test_code_contains_no_mutating_sql_or_insecure_odbc_fallback():
    body = SOURCE.read_text(encoding="utf-8")
    for forbidden in ("shell=True", "SetValueEx(", "StartServiceW(",
                      "CREATE DATABASE", "ALTER LOGIN", "TrustServerCertificate=Yes",
                      "Encrypt=No", "os.system("):
        assert forbidden not in body
    assert "locator.inspect_connection(connection)" in body
