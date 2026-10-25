#!/usr/bin/env python3
"""Bounded local-only SQL Server certificate binding and TDS PRELOGIN inventory.

Reads allowlisted HKLM metadata, sends one fixed PRELOGIN to localhost:1433,
never attempts LOGIN7, reads private keys, disables TLS, or accesses SQL data.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
from typing import Any, Callable

import noteri_native_qualification as native
import noteri_sql_network_inventory as network
import noteri_sql_local_tcp_probe as tcp

STORE_ROOT = r"SOFTWARE\Microsoft\SystemCertificates\MY\Certificates"
CERT_HEX = re.compile(r"[0-9a-fA-F]{40}\Z")
INSTANCE_ID = re.compile(r"MSSQL17\.MSSQLSERVER\Z")
ENC_MODES = {0: "off", 1: "on", 2: "not_supported", 3: "required"}
# PRELOGIN_VERSION is required and must be first, followed by ENCRYPTION=ON.
# Offsets are relative to the prelogin body (11-byte token table + 7-byte data).
PRELOGIN_BODY = bytes.fromhex("00 00 0b 00 06 01 00 11 00 01 ff 00 00 00 00 00 00 01")
PRELOGIN_PACKET = bytes((0x12, 0x01, 0, len(PRELOGIN_BODY) + 8, 0, 0, 1, 0)) + PRELOGIN_BODY
MAX_PACKET_LENGTH = 2048


class Blocked(ValueError):
    pass


class ProtocolUnverified(ValueError):
    pass


def _read_optional(registry: Any, key: Any, value: str) -> Any:
    if value not in {"MSSQLSERVER", "Certificate"}:
        raise Blocked("registry_field_not_allowlisted")
    try:
        return registry.QueryValueEx(key, value)[0]
    except FileNotFoundError:
        return None


def certificate_binding(registry: Any) -> dict[str, Any]:
    """Read the configured binding only; never open a certificate/private-key blob."""
    access = registry.KEY_READ | registry.KEY_WOW64_64KEY
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, network.INSTANCE_INDEX, 0, access) as key:
        instance = _read_optional(registry, key, "MSSQLSERVER")
    if not isinstance(instance, str) or not INSTANCE_ID.fullmatch(instance):
        raise Blocked("sql2025_registry_instance_unverified")
    path = network.INSTANCE_ROOT + "\\" + instance + r"\MSSQLServer\SuperSocketNetLib"
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path, 0, access) as key:
        certificate = _read_optional(registry, key, "Certificate")
    if certificate is None or certificate == "":
        return {
            "certificate_binding": "not_explicitly_configured",
            "configured_thumbprint_in_local_machine_my": None,
            "automatic_certificate_selection_unverified": True,
        }
    if not isinstance(certificate, str) or not CERT_HEX.fullmatch(certificate):
        raise Blocked("certificate_binding_format_invalid")
    # The thumbprint is used ONLY as a registry lookup, never exported.
    try:
        with registry.OpenKey(
            registry.HKEY_LOCAL_MACHINE,
            STORE_ROOT + "\\" + certificate.upper(), 0, access
        ):
            exists = True
    except FileNotFoundError:
        exists = False
    return {
        "certificate_binding": "explicit_store_entry_present" if exists else "explicit_store_entry_absent",
        "configured_thumbprint_in_local_machine_my": exists,
        "automatic_certificate_selection_unverified": False,
    }


def parse_prelogin_response(data: bytes) -> dict[str, Any]:
    """Check server response token bounds before reading encryption byte."""
    if not 6 <= len(data) <= MAX_PACKET_LENGTH - 8 or data[0] != 0:
        raise ProtocolUnverified("prelogin_payload_invalid")
    cursor, encryption, version, saw_version = 0, None, None, False
    end_table = -1
    while cursor < len(data):
        token = data[cursor]
        if token == 0xff:
            end_table = cursor + 1
            break
        if cursor + 5 > len(data) or (cursor == 0 and token != 0):
            raise ProtocolUnverified("prelogin_option_malformed")
        offset = int.from_bytes(data[cursor + 1:cursor + 3], "big")
        length = int.from_bytes(data[cursor + 3:cursor + 5], "big")
        if token == 0:
            if saw_version or length != 6:
                raise ProtocolUnverified("prelogin_version_invalid")
            saw_version = True
            version = (offset, length)
        elif token == 1:
            if encryption is not None or length != 1:
                raise ProtocolUnverified("prelogin_encryption_option_invalid")
            encryption = (offset, length)
        cursor += 5
        if cursor > 128:  # Disallow unbounded/malformed token tables.
            raise ProtocolUnverified("prelogin_option_limit")
    if end_table == -1 or not saw_version or encryption is None:
        raise ProtocolUnverified("prelogin_required_options_missing")
    assert version is not None
    if version[0] < end_table or version[0] + version[1] > len(data):
        raise ProtocolUnverified("prelogin_version_offset_invalid")
    offset, length = encryption
    if offset < end_table or offset + length > len(data):
        raise ProtocolUnverified("prelogin_encryption_offset_invalid")
    value = data[offset]
    if value not in ENC_MODES:
        raise ProtocolUnverified("prelogin_encryption_value_invalid")
    return {
        "tds_prelogin_response_valid": True,
        "tds_server_encryption_mode": ENC_MODES[value],
        "tds_encryption_negotiated": value in (1, 3),
    }


def _recv_exact(sock: Any, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise ProtocolUnverified("prelogin_connection_closed")
        result.extend(part)
    return bytes(result)


def tds_prelogin(dial: Callable[..., Any]) -> dict[str, Any]:
    """One TDS 7.x PRELOGIN only. No TLS ClientHello or SQL login is sent."""
    try:
        with dial(("127.0.0.1", 1433), timeout=3.0) as sock:
            sock.settimeout(3.0)
            sock.sendall(PRELOGIN_PACKET)
            header = _recv_exact(sock, 8)
            count = int.from_bytes(header[2:4], "big")
            if header[0] != 0x04 or count < 14 or count > MAX_PACKET_LENGTH or not header[1] & 0x01:
                raise ProtocolUnverified("tds_prelogin_packet_invalid")
            body = _recv_exact(sock, count - 8)
            return {"tds_prelogin_status": "response_received", **parse_prelogin_response(body)}
    except (TimeoutError, OSError, ProtocolUnverified):
        return {
            "tds_prelogin_status": "unavailable_or_invalid_response",
            "tds_prelogin_response_valid": False,
            "tds_server_encryption_mode": None,
            "tds_encryption_negotiated": False,
        }


def collect(expected_sha: str, correlation_id: str, registry: Any,
            dial: Callable[..., Any]) -> dict[str, Any]:
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
    if sql.get("status") != "observed" or not any(
        isinstance(item, dict) and item.get("instance") == "MSSQLSERVER"
        and item.get("service_state") == "running"
        and str(item.get("installed_version", "")).startswith("17.")
        for item in sql.get("instances", [])
    ):
        raise Blocked("sql2025_service_not_running")
    meta = network.read_network(registry)
    if meta.get("tcp_enabled") is not True or meta.get("tcp_listen_port_configured_ipall") is not True \
       or meta.get("tcp_dynamic_port_configured_ipall") is not False \
       or tcp.configured_port(registry) != 1433:
        raise Blocked("local_tcp_configuration_unverified")
    binding = certificate_binding(registry)
    protocol = tds_prelogin(dial)
    return {
        "status": "observed", "schema": "noteri-sql-certificate-tds-inventory/v1",
        "source_sha": expected_sha, "correlation_id": correlation_id,
        "host": "Noteri", "protocol": "tcp-local-only", "force_encryption": meta.get("force_encryption"),
        **binding, **protocol,
        "server_certificate_effective_identity_verified": False,
        "certificate_private_key_access_verified": False,
        "tls_certificate_chain_verified": False,
        "tls_certificate_hostname_verified": False,
        "sql_connection_authenticated": False,
        "sql_principal_readonly_verified": False,
        "report_builder_sql_preflight_passed": False,
        "business_rows_read": False,
        "registry_modified": False, "production_touched": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        import winreg
        result = collect(args.expected_sha, args.correlation_id, winreg,
                         socket.create_connection)
        exit_code = 0
    except (Blocked, native.Blocked, tcp.Blocked, network.Blocked) as exc:
        code = str(exc)
        allowed = {
            "noteri_windows_required", "source_sha_invalid", "source_sha_mismatch",
            "correlation_invalid", "normal_profile_required", "sql2025_service_not_running",
            "local_tcp_configuration_unverified", "certificate_binding_format_invalid",
            "sql2025_registry_instance_unverified", "protocol_setting_invalid", "port_config_invalid",
        }
        result = {"status": "blocked", "code": code if code in allowed else "certificate_inventory_unavailable"}
        exit_code = 2
    except Exception:
        result = {"status": "blocked", "code": "certificate_inventory_unavailable"}
        exit_code = 2
    result.setdefault("sql_connection_authenticated", False)
    result.setdefault("tls_certificate_chain_verified", False)
    result.setdefault("production_touched", False)
    result.setdefault("registry_modified", False)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
