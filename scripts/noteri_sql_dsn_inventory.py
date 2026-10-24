#!/usr/bin/env python3
"""Inventory only ODBC DSN metadata. Never connect, read secrets or change registry."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any

import noteri_native_qualification as native

ALLOWED_DRIVERS = frozenset((
    "ODBC Driver 17 for SQL Server",
    "ODBC Driver 18 for SQL Server",
))
LOCAL_SERVERS = frozenset(("noteri", "localhost", "127.0.0.1", "(local)", "."))
DATA_SOURCE_ROOT = r"SOFTWARE\ODBC\ODBC.INI"
REGISTRY_FIELDS = (
    "Server", "Database", "Trusted_Connection", "Encrypt", "TrustServerCertificate",
)
MAX_DSNS_PER_VIEW = 128


class Blocked(ValueError):
    """Expected safe failure; no raw registry values."""


def _has_dev_segment(text: Any) -> bool:
    return isinstance(text, str) and bool(
        re.search(r"(?:^|[_ .-])dev(?:$|[_ .-])", text, flags=re.IGNORECASE)
        or text.casefold().endswith("dev")
    ) and not re.search(r"prod|production|hml|stg", text, re.IGNORECASE)


def classify(name: str, driver: str, fields: dict[str, Any]) -> dict[str, bool]:
    """Only classify. No host, database or DSN names are returned."""
    server = fields.get("Server")
    db = fields.get("Database")
    auth = fields.get("Trusted_Connection")
    encrypt = fields.get("Encrypt")
    cert = fields.get("TrustServerCertificate")
    is_local = isinstance(server, str) and server.strip().casefold() in LOCAL_SERVERS
    is_dev = _has_dev_segment(name) and _has_dev_segment(db)
    is_integrated = isinstance(auth, str) and auth.strip().casefold() in {
        "yes", "true", "sspi"
    }
    is_encrypted = isinstance(encrypt, str) and encrypt.strip().casefold() in {
        "yes", "true", "mandatory", "strict"
    }
    validates_cert = isinstance(cert, str) and cert.strip().casefold() in {
        "no", "false"
    }
    is_driver18 = driver == "ODBC Driver 18 for SQL Server"
    return {
        "local_dev_metadata": bool(is_local and is_dev and is_driver18),
        "strict_tls_integrated_candidate": bool(
            is_local and is_dev and is_driver18 and is_integrated
            and is_encrypted and validates_cert
        ),
    }


def _optional_value(registry: Any, key: Any, field: str) -> Any:
    if field not in REGISTRY_FIELDS:
        raise Blocked("registry_field_not_allowlisted")
    try:
        value, _ = registry.QueryValueEx(key, field)
    except FileNotFoundError:
        return None
    return value


def inventory(registry: Any) -> dict[str, Any]:
    """Read HKLM/HKCU x 32/64 bit DSN registry views; never inspect credentials."""
    records: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    entry_count = 0
    for scope, hive in (
        ("system", registry.HKEY_LOCAL_MACHINE),
        ("user", registry.HKEY_CURRENT_USER),
    ):
        for flag in (registry.KEY_WOW64_64KEY, registry.KEY_WOW64_32KEY):
            access = registry.KEY_READ | flag
            try:
                sources = registry.OpenKey(
                    hive, DATA_SOURCE_ROOT + r"\ODBC Data Sources", 0, access
                )
            except FileNotFoundError:
                continue
            with sources:
                count = registry.QueryInfoKey(sources)[1]
                if count > MAX_DSNS_PER_VIEW or count < 0:
                    raise Blocked("dsn_count_limit")
                entry_count += count
                if entry_count > 4 * MAX_DSNS_PER_VIEW:
                    raise Blocked("dsn_total_limit")
                for i in range(count):
                    name, driver, _ = registry.EnumValue(sources, i)
                    if not isinstance(name, str) or not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9_. -]{0,63}", name
                    ):
                        raise Blocked("dsn_name_shape_invalid")
                    if driver not in ALLOWED_DRIVERS:
                        continue
                    try:
                        item = registry.OpenKey(
                            hive, DATA_SOURCE_ROOT + "\\" + name, 0, access
                        )
                    except FileNotFoundError:
                        raise Blocked("dsn_entry_not_found") from None
                    with item:
                        fields = {
                            field: _optional_value(registry, item, field)
                            for field in REGISTRY_FIELDS
                        }
                    key = (scope, name.casefold())
                    prior = records.get(key)
                    if prior is not None and prior != (driver, fields):
                        raise Blocked("dsn_registry_view_conflict")
                    records[key] = (driver, fields)

    classes = [classify(name, driver, fields) for (_, name), (driver, fields)
               in records.items()]
    return {
        "status": "observed",
        "data_source_registry_entries": entry_count,
        "sql_server_dsn_entries": len(records),
        "local_dev_metadata_entries": sum(x["local_dev_metadata"] for x in classes),
        "strict_tls_integrated_candidates": sum(
            x["strict_tls_integrated_candidate"] for x in classes
        ),
        "unambiguous_strict_candidate": sum(
            x["strict_tls_integrated_candidate"] for x in classes
        ) == 1,
        "dsn_value_exported": False,
        "credential_value_read": False,
        "sql_connection_tested": False,
        "sql_principal_readonly_verified": False,
        "database_identity_verified": False,
        "fabric_gateway_identity_verified": False,
        "registry_modified": False,
        "hml_verified": False,
        "production_touched": False,
    }


def observe(expected_sha: str, correlation_id: str) -> dict[str, Any]:
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
    import winreg
    return {
        **inventory(winreg),
        "schema_version": "noteri-odbc-dsn-inventory/v1",
        "host": "Noteri",
        "source_sha": expected_sha,
        "correlation_id": correlation_id,
        "profile_normal": True,
        "dsn_env_name_configured": bool(
            os.environ.get("REPORT_BUILDER_READ_ONLY_DSN", "").strip()
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = observe(args.expected_sha, args.correlation_id)
        code = 0
    except Blocked as exc:
        result = {
            "status": "blocked", "code": str(exc),
            "sql_connection_tested": False, "hml_verified": False,
            "production_touched": False,
        }
        code = 2
    except Exception:
        result = {
            "status": "blocked", "code": "native_metadata_unavailable",
            "sql_connection_tested": False, "hml_verified": False,
            "production_touched": False,
        }
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
