"""Sanitized SQL ERRORLOG inventory controls; no DB log or registry required."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

SRC = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_certificate_errorlog.py"

class NativeBlocked(ValueError):
    pass

native = types.ModuleType("noteri_native_qualification")
native.Blocked = NativeBlocked
native.source_head = lambda sha: sha
native.profile = lambda: {"profile": "NORMAL", "verified": True}
native.sql_inventory = lambda: {"status": "observed", "instances": [{"instance": "MSSQLSERVER", "installed_version": "17.0.1000.7", "service_state": "running"}]}
with patch.dict(sys.modules, {"noteri_native_qualification": native}):
    spec = importlib.util.spec_from_file_location("certlogtest", SRC)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

BASE = r"C:\Program Files\Microsoft SQL Server\MSSQL17.MSSQLSERVER\MSSQL"
ERRORLOG = BASE + r"\Log\ERRORLOG"


def test_errorlog_path_is_bound_to_setup_and_startup_parameter():
    assert m.log_target(BASE, ["-dother", "-e" + ERRORLOG, "-lother"]) == ERRORLOG


@pytest.mark.parametrize("startup,reason", [
    ([r"-eD:\Other\ERRORLOG"], "sql_errorlog_path_not_allowlisted"),
    (["-e" + ERRORLOG, "-e" + ERRORLOG], "sql_errorlog_argument_unverified"),
    (["-dother"], "sql_errorlog_argument_unverified"),
    (["-e" + BASE + r"\Log\..\secrets.txt"], "sql_errorlog_path_not_allowlisted"),
])
def test_log_path_rejects_diversion(startup, reason):
    with pytest.raises(m.Blocked, match=reason):
        m.log_target(BASE, startup)


def test_log_path_rejects_wrong_instance_even_if_self_consistent():
    other = BASE.replace("MSSQL17.MSSQLSERVER", "MSSQL17.OTHER")
    with pytest.raises(m.Blocked, match="sql_instance_path_unverified"):
        m.log_target(other, ["-e" + other + r"\Log\ERRORLOG"])


class Key:
    def __init__(self, mapping):
        self.mapping = mapping
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return None

class Registry:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    def __init__(self):
        self.fields = {"SQLPath": BASE, "SQLArg0": "-dother", "SQLArg1": "-e" + ERRORLOG, "SQLArg2": "-lother"}
        self.seen = []
    def OpenKey(self, hive, path, zero, access):
        assert hive == self.HKEY_LOCAL_MACHINE
        assert path in {m.SETUP, m.PARAMETERS}
        assert zero == 0 and access == (self.KEY_READ | self.KEY_WOW64_64KEY)
        self.seen.append(path)
        return Key(self.fields)
    def QueryValueEx(self, key, name):
        if name not in key.mapping:
            raise FileNotFoundError
        self.seen.append(name)
        return key.mapping[name], 1


def test_registered_path_uses_allowlisted_fields_and_does_not_mutate():
    r = Registry()
    assert m.registered_path(r) == (ERRORLOG, True)
    assert r.seen[:2] == [m.SETUP, "SQLPath"]
    assert "SQLArg1" in r.seen
    assert all("Blob" not in str(x) for x in r.seen)


@pytest.mark.parametrize("sample,expected", [
    ("Server A self-generated certificate was successfully loaded for encryption.", "self_generated_loaded"),
    ('Server The certificate [Cert Hash(sha1) "abc123"] was successfully loaded for encryption.', "store_certificate_loaded"),
    ("Server Unable to load user-specified certificate, PRIVATE-SERVER", "configured_certificate_load_failed"),
    ("Server The server could not load the certificate it needs", "certificate_load_failed"),
    ("Server Unable to initialize SSL encryption", "encryption_initialization_failed"),
    ("Server is listening on PRIVATE-SERVER; instance secret", "not_observed_in_current_log"),
])
def test_sanitized_startup_cert_classification(sample, expected):
    observed = m.classify_cert_log(sample)
    assert observed["certificate_startup_log_classification"] == expected
    for word in ("abc123", "PRIVATE-SERVER", "secret"):
        assert word not in json.dumps(observed)
    assert observed["current_service_generation_verified"] is False
    assert observed["actual_tls_certificate_verified"] is False


def test_most_recent_certificate_entry_wins():
    sample = "Server The certificate [Cert Hash(sha1) \"SECRET\"] was successfully loaded for encryption.\n"
    sample += "Server A self-generated certificate was successfully loaded for encryption.\n"
    assert m.classify_cert_log(sample)["certificate_startup_log_classification"] == "self_generated_loaded"


def test_read_file_bounded_and_16bit_decoding(tmp_path):
    file = tmp_path / "ERRORLOG"
    message = "Server A self-generated certificate was successfully loaded for encryption."
    file.write_bytes(("\ufeff" + message).encode("utf-16-le"))
    raw = m._safe_regular_file(file)
    assert m.classify_cert_log(m.decode_log(raw))["certificate_startup_log_classification"] == "self_generated_loaded"
    file.write_bytes(b"x" * 512)
    with patch.object(m, "MAX_BYTES", 256):
        with pytest.raises(m.Blocked, match="errorlog_size_or_type_unverified"):
            m._safe_regular_file(file)


def test_symlink_is_rejected_before_read(tmp_path):
    secret = tmp_path / "hidden"
    secret.write_text("PRIVATE-SERVER")
    link = tmp_path / "ERRORLOG"
    link.symlink_to(secret)
    with pytest.raises(m.Blocked, match="errorlog_reparse_point"):
        m._safe_regular_file(link)


def test_real_collection_contract_with_fake_log():
    content = b"Server A self-generated certificate was successfully loaded for encryption.\nPRIVATE-SERVER"
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m, "registered_path", return_value=(ERRORLOG, True)), \
         patch.object(m, "_safe_regular_file", return_value=content):
        value = m.collect("a" * 40, "sqlcert-log-20261025", Registry())
    assert value["status"] == "observed"
    assert value["startup_log_argument_verified"] is True
    assert value["certificate_startup_log_classification"] == "self_generated_loaded"
    assert value["sql_authenticated"] is False and value["production_touched"] is False
    assert "PRIVATE-SERVER" not in json.dumps(value)


def test_sha_invalid_and_profile_study_block_before_file_read():
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m, "registered_path") as read:
        with pytest.raises(m.Blocked, match="source_sha_invalid"):
            m.collect("bad", "sqlcert-log-20261025", Registry())
        with patch.object(native, "profile", return_value={"profile": "ESTUDO", "verified": True}):
            with pytest.raises(m.Blocked, match="normal_profile_required"):
                m.collect("a" * 40, "sqlcert-log-20261025", Registry())
        read.assert_not_called()


def test_repeat_classification_identical_and_source_nondestructive():
    sample = "Server A self-generated certificate was successfully loaded for encryption."
    assert m.classify_cert_log(sample) == m.classify_cert_log(sample)
    code = SRC.read_text()
    for item in ("SetValueEx", "SQL INSERT", "CREATE DATABASE", "ALTER LOGIN",
                 "TrustServerCertificate=Yes", "Encrypt=No", "shell=True", "Popen(", "os.system("):
        assert item not in code


def test_absent_setup_or_parameters_classified_without_leak():
    with patch.object(Registry, "OpenKey", side_effect=FileNotFoundError):
        with pytest.raises(m.Blocked, match="sql_setup_path_absent"):
            m.registered_path(Registry())
    class MissingParameters(Registry):
        def OpenKey(self, hive, path, zero, access):
            if path == m.PARAMETERS:
                raise FileNotFoundError
            return super().OpenKey(hive, path, zero, access)
    with pytest.raises(m.Blocked, match="sql_startup_parameters_absent"):
        m.registered_path(MissingParameters())


def test_missing_errorlog_file_classified_without_path_exposure(tmp_path):
    target = tmp_path / "ERRORLOG"
    with pytest.raises(m.Blocked, match="sql_errorlog_file_absent") as exc:
        m._safe_regular_file(target)
    assert str(target) not in str(exc.value)

def test_registry_denied_uses_setup_candidate_without_claiming_binding():
    class DeniedParameters(Registry):
        def OpenKey(self, hive, path, zero, access):
            if path == m.PARAMETERS:
                raise PermissionError("private details")
            return super().OpenKey(hive, path, zero, access)
    result = m.registered_path(DeniedParameters())
    assert result == (ERRORLOG, False)


def test_registry_denied_with_untrusted_setup_still_fails_closed():
    r = Registry()
    r.fields["SQLPath"] = r"C:\Other\MSSQL17.MSSQLSERVER\MSSQL"
    class DeniedParameters(Registry):
        def OpenKey(self, hive, path, zero, access):
            if path == m.PARAMETERS:
                raise PermissionError
            return super().OpenKey(hive, path, zero, access)
    denied = DeniedParameters()
    denied.fields["SQLPath"] = r"D:\Other\MSSQL17.OTHER\MSSQL"
    with pytest.raises(m.Blocked, match="sql_instance_path_unverified"):
        m.registered_path(denied)


def test_unverified_candidate_never_promotes_to_current_certificate(tmp_path):
    file = tmp_path / "ERRORLOG"
    file.write_text("Server A self-generated certificate was successfully loaded for encryption.")
    with patch.object(m.os, "name", "nt"), patch.object(m.socket, "gethostname", return_value="Noteri"), \
         patch.object(m, "registered_path", return_value=(ERRORLOG, False)), \
         patch.object(m, "_safe_regular_file", return_value=file.read_bytes()):
        result = m.collect("a" * 40, "sqlcert-log-20261025", Registry())
    assert result["certificate_startup_log_classification"] == "self_generated_loaded"
    assert result["startup_log_argument_verified"] is False
    assert result["log_source"] == "unverified_setup_candidate"
    assert result["current_service_generation_verified"] is False
    assert result["actual_tls_certificate_verified"] is False
