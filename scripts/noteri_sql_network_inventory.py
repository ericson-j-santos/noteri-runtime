#!/usr/bin/env python3
"""Read-only SQL Server 2025 network protocol registry inventory on Noteri."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any

import noteri_native_qualification as native

INSTANCE_INDEX = r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
INSTANCE_ROOT = r"SOFTWARE\Microsoft\Microsoft SQL Server"


class Blocked(ValueError):
    pass


def _value(registry: Any, key: Any, name: str) -> Any:
    if name not in {
        "MSSQLSERVER", "Enabled", "ListenOnAllIPs", "TcpPort",
        "TcpDynamicPorts", "ForceEncryption",
    }:
        raise Blocked("registry_value_not_allowlisted")
    try:
        return registry.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if type(value) is not int or value not in (0, 1):
        raise Blocked("protocol_setting_invalid")
    return bool(value)


def _port_set(value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(
        r"[0-9, ]*", value
    ):
        raise Blocked("port_config_invalid")
    return bool(value.strip())


def read_network(registry: Any) -> dict[str, Any]:
    access = registry.KEY_READ | registry.KEY_WOW64_64KEY
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, INSTANCE_INDEX, 0, access) as root:
        instance_id = _value(registry, root, "MSSQLSERVER")
    if not isinstance(instance_id, str) or not re.fullmatch(
        r"MSSQL[0-9]{1,2}\.MSSQLSERVER", instance_id
    ):
        raise Blocked("instance_registry_identity_invalid")
    base = INSTANCE_ROOT + "\\" + instance_id + r"\MSSQLServer\SuperSocketNetLib"

    def read_protocol(sub: str) -> bool | None:
        try:
            with registry.OpenKey(registry.HKEY_LOCAL_MACHINE,
                                  base + "\\" + sub, 0, access) as key:
                return _optional_bool(_value(registry, key, "Enabled"))
        except FileNotFoundError:
            return None

    tcp = read_protocol("Tcp")
    pipes = read_protocol("Np")
    shared = read_protocol("Sm")
    try:
        with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, base, 0, access) as k:
            forced = _optional_bool(_value(registry, k, "ForceEncryption"))
    except FileNotFoundError:
        forced = None
    try:
        with registry.OpenKey(registry.HKEY_LOCAL_MACHINE,
                              base + r"\Tcp\IPAll", 0, access) as k:
            static_port = _port_set(_value(registry, k, "TcpPort"))
            dynamic_port = _port_set(_value(registry, k, "TcpDynamicPorts"))
    except FileNotFoundError:
        static_port = dynamic_port = None
    return {
        "status": "observed",
        "tcp_enabled": tcp,
        "named_pipes_enabled": pipes,
        "shared_memory_enabled": shared,
        "tcp_listen_port_configured_ipall": static_port,
        "tcp_dynamic_port_configured_ipall": dynamic_port,
        "force_encryption": forced,
        "tcp_readiness_comprovable": tcp is True and (
            static_port is True or dynamic_port is True
        ),
        "database_connection_tested": False,
        "sql_permissions_verified": False,
        "certificate_validated": False,
        "registry_modified": False,
        "production_touched": False,
    }


def collect(expected_sha: str, correlation_id: str) -> dict[str, Any]:
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
        x.get("instance") == "MSSQLSERVER" and x.get("service_state") == "running"
        and str(x.get("installed_version", "")).startswith("17.")
        for x in sql.get("instances", []) if isinstance(x, dict)
    ):
        raise Blocked("local_sql2025_unavailable")
    import winreg
    return {
        **read_network(winreg), "host": "Noteri", "source_sha": expected_sha,
        "correlation_id": correlation_id, "schema": "noteri-sql-network-metadata/v1",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = collect(args.expected_sha, args.correlation_id)
        code = 0
    except Blocked as exc:
        result = {"status": "blocked", "code": str(exc),
                  "registry_modified": False, "production_touched": False}
        code = 2
    except Exception:
        result = {"status": "blocked", "code": "network_registry_metadata_unavailable",
                  "registry_modified": False, "production_touched": False}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
