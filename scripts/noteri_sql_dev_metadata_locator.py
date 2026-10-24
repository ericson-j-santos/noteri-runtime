#!/usr/bin/env python3
"""Fixed read-only local SQL Server metadata discovery; no business tables or writes."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any, Callable

import noteri_native_qualification as native
from noteri_sql_dsn_inventory import _has_dev_segment

IDENTITY_SQL = (
    "SELECT CONVERT(nvarchar(256), SERVERPROPERTY(N'ServerName')), "
    "DB_NAME(), IS_SRVROLEMEMBER(N'sysadmin')"
)
CATALOG_SQL = (
    "SELECT name FROM sys.databases "
    "WHERE database_id > 4 AND state_desc = N'ONLINE'"
)
ODBC_LOCAL = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=localhost;DATABASE=master;"
    "Trusted_Connection=Yes;Encrypt=Yes;TrustServerCertificate=No;"
    "ApplicationIntent=ReadOnly;Connection Timeout=5"
)


class Blocked(ValueError):
    pass


def inspect_connection(conn: Any) -> dict[str, Any]:
    """Only fixed metadata reads, with no database/login names in the result."""
    cursor = conn.cursor()
    try:
        cursor.execute(IDENTITY_SQL)
        row = cursor.fetchone()
        if row is None or len(row) != 3:
            raise Blocked("local_instance_identity_unavailable")
        server, database, admin = row
        if not isinstance(server, str) or server.casefold() != "noteri":
            raise Blocked("local_instance_identity_mismatch")
        if not isinstance(database, str) or database.casefold() != "master":
            raise Blocked("metadata_database_mismatch")
        if admin != 0:
            raise Blocked("integrated_identity_not_restricted")
        cursor.execute(CATALOG_SQL)
        rows = cursor.fetchall()
        if not isinstance(rows, (tuple, list)) or len(rows) > 128:
            raise Blocked("catalog_size_unverified")
        names = []
        for entry in rows:
            if entry is None or len(entry) != 1 or not isinstance(entry[0], str):
                raise Blocked("catalog_entry_invalid")
            name = entry[0]
            if not re.fullmatch(r"[A-Za-z0-9_ .-]{1,128}", name):
                raise Blocked("catalog_entry_invalid")
            names.append(name)
        candidates = [x for x in names if _has_dev_segment(x)]
        return {
            "status": "observed",
            "visible_non_system_databases": len(names),
            "visible_dev_database_candidates": len(candidates),
            "unique_visible_dev_database": len(candidates) == 1,
            "integrated_identity_is_sysadmin": False,
            "tls_and_certificate_validation_required": True,
            "sql_connection_tested": True,
            "database_identity_verified": False,
            "sql_principal_readonly_verified": False,
            "report_builder_sql_preflight_passed": False,
            "fabric_gateway_identity_verified": False,
            "production_touched": False,
            "data_mutations_performed": False,
            "business_rows_read": False,
        }
    finally:
        cursor.close()


def collect(expected_sha: str, correlation_id: str, connect: Callable[..., Any]) -> dict[str, Any]:
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
        item.get("instance") == "MSSQLSERVER"
        and str(item.get("installed_version", "")).startswith("17.")
        and item.get("service_state") == "running"
        for item in sql.get("instances", [])
        if isinstance(item, dict)
    ):
        raise Blocked("local_sql2025_not_ready")
    if "ODBC Driver 18 for SQL Server" not in sql.get("odbc_drivers", []):
        raise Blocked("odbc18_driver_missing")
    conn = connect(ODBC_LOCAL, timeout=5, autocommit=True)
    try:
        result = inspect_connection(conn)
    finally:
        conn.close()
    return {
        **result,
        "schema_version": "noteri-sql-dev-metadata-locator/v1",
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
        import pyodbc
        pyodbc.pooling = False
        result = collect(args.expected_sha, args.correlation_id, pyodbc.connect)
        code = 0
    except Blocked as exc:
        result = {"status": "blocked", "code": str(exc),
                  "sql_principal_readonly_verified": False,
                  "database_identity_verified": False,
                  "production_touched": False}
        code = 2
    except Exception:
        result = {"status": "blocked", "code": "local_secure_sql_metadata_unavailable",
                  "sql_principal_readonly_verified": False,
                  "database_identity_verified": False,
                  "production_touched": False}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
