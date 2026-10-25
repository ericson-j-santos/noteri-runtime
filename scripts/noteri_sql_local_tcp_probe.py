#!/usr/bin/env python3
"""Check only the configured local SQL Server TCP listener; never send SQL."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any, Callable

import noteri_native_qualification as native
import noteri_sql_network_inventory as network


class Blocked(ValueError):
    pass


def configured_port(registry: Any) -> int:
    access = registry.KEY_READ | registry.KEY_WOW64_64KEY
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, network.INSTANCE_INDEX, 0, access) as k:
        internal_name = network._value(registry, k, "MSSQLSERVER")
    if not isinstance(internal_name, str) or not re.fullmatch(
        r"MSSQL[0-9]{1,2}\.MSSQLSERVER", internal_name
    ):
        raise Blocked("local_instance_registry_unverified")
    path = (network.INSTANCE_ROOT + "\\" + internal_name
            + r"\MSSQLServer\SuperSocketNetLib\Tcp\IPAll")
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path, 0, access) as k:
        raw = network._value(registry, k, "TcpPort")
        dynamic = network._value(registry, k, "TcpDynamicPorts")
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,5}", raw):
        raise Blocked("single_static_tcp_port_required")
    port = int(raw)
    if not 1 <= port <= 65535:
        raise Blocked("invalid_port_range")
    if dynamic not in ("", None):
        raise Blocked("dynamic_tcp_port_unsupported")
    return port


def check_listener(registry: Any, dial: Callable[..., Any]) -> dict[str, Any]:
    meta = network.read_network(registry)
    if meta.get("tcp_enabled") is not True:
        raise Blocked("tcp_not_enabled")
    if meta.get("tcp_listen_port_configured_ipall") is not True:
        raise Blocked("tcp_static_port_missing")
    if meta.get("tcp_dynamic_port_configured_ipall") is not False:
        raise Blocked("tcp_dynamic_state_ambiguous")
    port = configured_port(registry)
    try:
        with dial(("127.0.0.1", port), timeout=2.0):
            reachable = True
    except (OSError, TimeoutError):
        reachable = False
    return {
        "status": "observed",
        "tcp_loopback_listener_responded": reachable,
        "default_tcp_port_configured": port == 1433,
        "socket_attempted": True,
        "sql_login_attempted": False,
        "sql_connection_tested": False,
        "sql_permissions_verified": False,
        "tls_certificate_verified": False,
        "database_identity_verified": False,
        "fabric_identity_verified": False,
        "business_data_read": False,
        "registry_modified": False,
        "production_touched": False,
    }


def collect(expected_sha: str, correlation_id: str,
            registry: Any, dial: Callable[..., Any]) -> dict[str, Any]:
    if os.name != "nt" or socket.gethostname().casefold() != "noteri":
        raise Blocked("noteri_windows_required")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise Blocked("source_sha_invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", correlation_id):
        raise Blocked("correlation_invalid")
    native.source_head(expected_sha)
    profile = native.profile()
    if profile.get("verified") is not True or profile.get("profile") != "NORMAL":
        raise Blocked("normal_profile_required")
    sql = native.sql_inventory()
    if not any(
        isinstance(row, dict) and row.get("instance") == "MSSQLSERVER"
        and row.get("service_state") == "running"
        and str(row.get("installed_version", "")).startswith("17.")
        for row in sql.get("instances", [])
    ):
        raise Blocked("local_sql2025_not_running")
    return {
        **check_listener(registry, dial),
        "schema": "noteri-sql-local-tcp-probe/v1", "host": "Noteri",
        "source_sha": expected_sha, "correlation_id": correlation_id,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        import winreg
        result = collect(args.expected_sha, args.correlation_id,
                         winreg, socket.create_connection)
        code = 0
    except Blocked as exc:
        result = {"status": "blocked", "code": str(exc),
                  "sql_connection_tested": False, "production_touched": False}
        code = 2
    except Exception:
        result = {"status": "blocked", "code": "local_tcp_probe_unavailable",
                  "sql_connection_tested": False, "production_touched": False}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
