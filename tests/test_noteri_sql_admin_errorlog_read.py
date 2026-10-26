"""Offline security contracts for the opt-in SQL ERRORLOG administrative read."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "scripts" / "noteri_sql_admin_errorlog_read.py"
if str(SRC.parent) not in sys.path:
    sys.path.insert(0, str(SRC.parent))

# Runtime imports an existing read-only collector; these tests never touch the host.
with patch.dict(sys.modules, {"noteri_sql_certificate_errorlog": Mock(collect=Mock())}):
    spec = importlib.util.spec_from_file_location("noteri_sql_admin_errorlog_read_test", SRC)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

SHA = "a" * 40
CORRELATION = "rb-sql-cert-dev-20261026"


def sample(**replacements):
    value = {
        "status": "observed", "schema": "noteri-sql-certificate-log-inventory/v1",
        "host": "Noteri", "source_sha": SHA, "correlation_id": CORRELATION,
        "startup_log_argument_verified": True,
        "log_source": "registered_argument",
        "certificate_startup_log_classification": "self_generated_loaded",
        "certificate_startup_marker_observed": True,
        "current_service_generation_verified": False,
        "actual_tls_certificate_verified": False,
        "tls_trust_chain_verified": False,
        "sql_authenticated": False, "business_data_read": False,
        "registry_modified": False, "production_touched": False,
    }
    value.update(replacements)
    return value


def invoke(reader, **options):
    arguments = {
        "environment": "dev", "confirmation": module.CONFIRM,
        "registry": object(), "host": "Noteri", "platform": "nt",
        "admin_check": lambda: True, "reader": reader,
    }
    arguments.update(options)
    return module.collect(SHA, CORRELATION, **arguments)


def test_admin_positive_is_sanitized_and_deterministic():
    reader = Mock(return_value=sample())
    once = invoke(reader)
    twice = invoke(reader)
    assert once == twice
    assert reader.call_count == 2
    assert once["certificate_startup_log_classification"] == "self_generated_loaded"
    assert once["startup_log_argument_verified"] is True
    assert once["actual_tls_certificate_verified"] is False
    assert once["status"] == "observed"
    assert "PRIVATE-PATH" not in json.dumps(once)
    assert "sql_password" not in json.dumps(once)
    assert "log_source" not in once


@pytest.mark.parametrize("change,code", [
    ({"host": "Desktop"}, "noteri_windows_required"),
    ({"platform": "posix"}, "noteri_windows_required"),
    ({"environment": "prod"}, "dev_environment_required"),
    ({"confirmation": "NO"}, "confirmation_invalid"),
    ({"admin_check": lambda: False}, "admin_identity_required"),
])
def test_preflight_rejects_without_read(change, code):
    reader = Mock()
    with pytest.raises(module.Blocked, match=code):
        invoke(reader, **change)
    reader.assert_not_called()


@pytest.mark.parametrize("key,value,code", [
    ("status", "blocked", "active_startup_argument_unverified"),
    ("schema", "unknown", "active_startup_argument_unverified"),
    ("source_sha", "b" * 40, "active_startup_argument_unverified"),
    ("startup_log_argument_verified", False, "active_startup_argument_unverified"),
    ("log_source", "unverified_setup_candidate", "active_startup_argument_unverified"),
    ("certificate_startup_log_classification", "unknown", "certificate_classification_invalid"),
    ("certificate_startup_marker_observed", False, "certificate_marker_inconsistent"),
    ("sql_authenticated", True, "collector_security_contract_invalid"),
    ("registry_modified", True, "collector_security_contract_invalid"),
    ("actual_tls_certificate_verified", True, "collector_security_contract_invalid"),
])
def test_readback_refuses_incomplete_or_unsafe_evidence(key, value, code):
    reader = Mock(return_value=sample(**{key: value}))
    with pytest.raises(module.Blocked, match=code):
        invoke(reader)


def test_unexpected_payload_and_private_fields_are_rejected():
    with pytest.raises(module.Blocked, match="collector_contract_invalid"):
        invoke(Mock(return_value={**sample(), "errorlog_path": "PRIVATE-PATH"}))
    with pytest.raises(module.Blocked, match="collector_contract_invalid"):
        invoke(Mock(return_value=None))


def test_valid_not_observed_keeps_tls_unverified():
    value = sample(certificate_startup_log_classification="not_observed_in_current_log",
                   certificate_startup_marker_observed=False)
    result = invoke(Mock(return_value=value))
    assert result["certificate_startup_marker_observed"] is False
    assert result["tls_trust_chain_verified"] is False


def test_cli_non_windows_blocked_without_importing_registry(capsys):
    rc = module.main(["--expected-sha", SHA, "--correlation-id", CORRELATION,
                      "--environment", "dev", "--confirm", module.CONFIRM])
    outcome = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert outcome["status"] == "blocked"
    assert outcome["code"] == "noteri_windows_required"


def test_code_exposes_no_writes_credentials_or_elevation():
    code = SRC.read_text(encoding="utf-8")
    for unsafe in ("ShellExecute", "runas", "SetValueEx", "ChangeServiceConfig",
                   "schtasks", "subprocess.run", "TrustServerCertificate=Yes",
                   "Encrypt=No", "os.system(", "CREATE LOGIN"):
        assert unsafe not in code
