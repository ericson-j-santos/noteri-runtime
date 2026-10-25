#!/usr/bin/env python3
"""Fail-closed ODBC 18 TLS/TCP diagnostic scoped to the Noteri loopback listener."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any, Callable

import noteri_native_qualification as native
import noteri_sql_local_tcp_probe as tcp
import noteri_sql_dev_metadata_locator as locator

# The loopback address cannot reach another host. HostNameInCertificate verifies
# the expected Noteri identity rather than accepting a certificate for an IP.
# This is an explicit Driver 18 secure connection, never a TLS bypass.
ODBC_TCP = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=tcp:127.0.0.1,1433;HostNameInCertificate=Noteri;"
    "DATABASE=master;Trusted_Connection=Yes;"
    "Encrypt=Yes;TrustServerCertificate=No;"
    "ApplicationIntent=ReadOnly;Connection Timeout=5"
)

class Blocked(ValueError):
    """Fixed, non-sensitive refusal reason."""

def _safe_error(exc: Exception) -> str:
    """Classify a driver exception without returning its potentially private text."""
    args = getattr(exc, "args", ())
    state = str(args[0]).strip().upper() if args else ""
    if not re.fullmatch(r"[A-Z0-9]{5}", state):
        state = ""
    details = " ".join(str(part) for part in args).casefold()[:4096]
    if ("certificate" in details or "certificad" in details or "certificat" in details):
        if any(word in details for word in (
            "target principal name", "subject name does not match",
            "hostname mismatch", "host name", "name mismatch",
            "nome principal", "nome de host",
        )):
            return "tls_certificate_name_mismatch"
        if any(word in details for word in (
            "not trusted", "untrusted", "trust chain", "certificate chain",
            "verify failed", "issuer certificate", "cadeia",
            "autoridade certificadora",
        )):
            return "tls_certificate_trust_failure"
        return "tls_certificate_other_failure"
    if state == "28000":
        return "integrated_authentication_rejected"
    if state in {"IM002", "IM003"}:
        return "odbc_driver_configuration_unavailable"
    if "10061" in details or "actively refused" in details:
        return "sql_tcp_connection_refused"
    if state in {"HYT00", "HYT01"}:
        return "sql_connection_timeout"
    if any(value in details for value in ("ssl provider", "tls handshake", "schannel")):
        return "tls_negotiation_unclassified"
    if state in {"08001", "08004", "08S01"}:
        return "sql_transport_or_tls_unclassified"
    return "odbc_error_unclassified"


def check_guard(expected_sha: str, correlation_id: str) -> None:
    if os.name != "nt" or socket.gethostname().casefold() != "noteri":
        raise Blocked("noteri_windows_required")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise Blocked("source_sha_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", correlation_id):
        raise Blocked("correlation_id_invalid")
    native.source_head(expected_sha)
    profile = native.profile()
    if profile.get("verified") is not True or profile.get("profile") != "NORMAL":
        raise Blocked("normal_profile_required")
    sql = native.sql_inventory()
    if sql.get("status") != "observed" or not any(
        isinstance(x, dict) and x.get("instance") == "MSSQLSERVER"
        and x.get("service_state") == "running"
        and str(x.get("installed_version", "")).startswith("17.")
        for x in sql.get("instances", [])
    ):
        raise Blocked("local_sql2025_not_running")
    if "ODBC Driver 18 for SQL Server" not in sql.get("odbc_drivers", []):
        raise Blocked("odbc18_not_installed")


def diagnostic(
    registry: Any,
    dial: Callable[..., Any],
    connect: Callable[..., Any],
) -> dict[str, Any]:
    """Use only local loopback TCP and metadata; never modify server configuration."""
    listener = tcp.check_listener(registry, dial)
    if not listener.get("default_tcp_port_configured"):
        raise Blocked("nonstandard_local_tcp_port_not_allowlisted")
    if listener.get("tcp_loopback_listener_responded") is not True:
        raise Blocked("local_tcp_listener_not_responding")
    try:
        connection = connect(ODBC_TCP, timeout=5, autocommit=True)
    except Exception as exc:
        return {
            "status": "blocked", "code": _safe_error(exc),
            "tcp_loopback_listener_responded": True,
            "sql_login_succeeded": False,
            "sql_principal_readonly_verified": False,
            "tls_certificate_validated": False,
            "report_builder_sql_preflight_passed": False,
            "database_identity_verified": False,
            "business_rows_read": False, "data_mutations_performed": False,
            "production_touched": False,
        }
    try:
        result = locator.inspect_connection(connection)
    finally:
        connection.close()
    return {
        **result,
        "tcp_loopback_listener_responded": True,
        "sql_login_succeeded": True,
        # Contractually verified by Driver 18 when TLS is mandatory and
        # TrustServerCertificate=No, not by an independent certificate parser.
        "tls_certificate_validated_by_odbc18": True,
        "sql_principal_readonly_verified": False,
    }


def collect(expected_sha: str, correlation_id: str,
            registry: Any, dial: Callable[..., Any],
            connect: Callable[..., Any]) -> dict[str, Any]:
    check_guard(expected_sha, correlation_id)
    return {
        **diagnostic(registry, dial, connect),
        "schema": "noteri-sql-secure-tcp-probe/v1",
        "host": "Noteri",
        "source_sha": expected_sha,
        "correlation_id": correlation_id,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        import winreg
        import pyodbc
        pyodbc.pooling = False
        value = collect(args.expected_sha, args.correlation_id, winreg,
                        socket.create_connection, pyodbc.connect)
        exit_code = 0 if value["status"] == "observed" else 2
    except (Blocked, native.Blocked, tcp.Blocked, locator.Blocked) as exc:
        known_codes = {
            "noteri_windows_required", "source_sha_invalid", "source_sha_mismatch",
            "correlation_id_invalid", "normal_profile_required",
            "local_sql2025_not_running", "odbc18_not_installed",
            "nonstandard_local_tcp_port_not_allowlisted",
            "local_tcp_listener_not_responding", "tcp_not_enabled",
            "tcp_static_port_missing", "tcp_dynamic_state_ambiguous",
            "metadata_database_mismatch", "local_instance_identity_mismatch",
            "local_instance_identity_unavailable", "integrated_identity_not_restricted",
            "catalog_size_unverified", "catalog_entry_invalid",
        }
        code = str(exc)
        value = {"status": "blocked",
                 "code": code if code in known_codes else "sql_probe_precondition_unverified"}
        exit_code = 2
    except ImportError:
        value = {"status": "blocked", "code": "odbc18_python_connector_unavailable"}
        exit_code = 2
    except Exception:
        value = {"status": "blocked", "code": "secure_tcp_probe_unavailable"}
        exit_code = 2
    value.setdefault("sql_principal_readonly_verified", False)
    value.setdefault("database_identity_verified", False)
    value.setdefault("tls_certificate_validated", False)
    value.setdefault("report_builder_sql_preflight_passed", False)
    value.setdefault("data_mutations_performed", False)
    value.setdefault("production_touched", False)
    print(json.dumps(value, ensure_ascii=True, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
