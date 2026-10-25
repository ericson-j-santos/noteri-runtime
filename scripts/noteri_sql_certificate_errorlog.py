#!/usr/bin/env python3
"""Sanitized SQL Server 2025 certificate-startup inventory from its local ERRORLOG.

Reads only the configured SQL startup log at the registered installation path.
Does not output raw log lines, thumbprints, paths, identities, or credentials.
"""
from __future__ import annotations

import argparse
import json
import ntpath
import os
from pathlib import Path
import re
import socket
import stat
from typing import Any

import noteri_native_qualification as native

INSTANCE_ROOT = r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL17.MSSQLSERVER"
SETUP = INSTANCE_ROOT + r"\Setup"
PARAMETERS = INSTANCE_ROOT + r"\MSSQLServer\Parameters"
MAX_BYTES = 8 * 1024 * 1024
MAX_ARGS = 8


class Blocked(ValueError):
    pass


def log_target(sql_path: str, startup_args: list[str]) -> str:
    """Bind -e to SQLPath/Log/ERRORLOG; no caller-selected file or directory."""
    if (not isinstance(sql_path, str) or not re.fullmatch(
        r"[A-Za-z]:\\[^\r\n]+", sql_path
    )):
        raise Blocked("sql_install_path_invalid")
    if len(startup_args) > MAX_ARGS or not all(isinstance(v, str) for v in startup_args):
        raise Blocked("sql_startup_arguments_invalid")
    roots = [a[2:] for a in startup_args if a.lower().startswith("-e")]
    if len(roots) != 1:
        raise Blocked("sql_errorlog_argument_unverified")
    base = ntpath.normcase(ntpath.normpath(sql_path.rstrip("\\/")))
    target = ntpath.normcase(ntpath.normpath(roots[0]))
    expected = ntpath.normcase(ntpath.join(base, "Log", "ERRORLOG"))
    if target != expected or not ntpath.isabs(target):
        raise Blocked("sql_errorlog_path_not_allowlisted")
    if "mssql17.mssqlserver" not in [s.casefold() for s in ntpath.normpath(sql_path).split("\\")]:
        raise Blocked("sql_instance_path_unverified")
    return roots[0]


def registered_path(registry: Any) -> tuple[str, bool]:
    """Bounded HKLM read; no SQLArg values are emitted outside this function."""
    access = registry.KEY_READ | registry.KEY_WOW64_64KEY
    try:
        with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, SETUP, 0, access) as key:
            base = registry.QueryValueEx(key, "SQLPath")[0]
    except FileNotFoundError:
        raise Blocked("sql_setup_path_absent") from None
    except PermissionError:
        raise Blocked("sql_setup_path_denied") from None
    args = []
    try:
        with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, PARAMETERS, 0, access) as key:
            for i in range(MAX_ARGS):
                try:
                    value = registry.QueryValueEx(key, f"SQLArg{i}")[0]
                except FileNotFoundError:
                    continue
                args.append(value)
    except FileNotFoundError:
        raise Blocked("sql_startup_parameters_absent") from None
    except PermissionError:
        # No elevation or bypass: a best-effort candidate under the SQLPath
        # read earlier, NOT verified as the active -e startup argument.
        default_path = ntpath.join(str(base).rstrip("\\/"), "Log", "ERRORLOG")
        return log_target(base, ["-e" + default_path]), False
    return log_target(base, args), True


def _safe_regular_file(path: Path) -> bytes:
    """Refuse reparse points/junctions and limit bytes; do not return path/log."""
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & 0x400):
                raise Blocked("errorlog_reparse_point")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise Blocked("errorlog_size_or_type_unverified")
        with path.open("rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise Blocked("sql_errorlog_file_absent") from None
    except PermissionError:
        raise Blocked("sql_errorlog_file_denied") from None
    if len(raw) != info.st_size or len(raw) > MAX_BYTES:
        raise Blocked("errorlog_changed_during_read")
    return raw


def decode_log(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if b"\x00" in raw[:128]:
        return raw.decode("utf-16-le")
    return raw.decode("utf-8-sig", errors="replace")


def classify_cert_log(text: str) -> dict[str, Any]:
    """Only known Microsoft SQL Server certificate startup messages are allowed."""
    kinds = []
    for line in text.splitlines():
        low = line.casefold()
        if "a self-generated certificate was successfully loaded for encryption" in low:
            kinds.append("self_generated_loaded")
        elif "the certificate [cert hash(sha1)" in low and "was successfully loaded for encryption" in low:
            kinds.append("store_certificate_loaded")
        elif "unable to load user-specified certificate" in low:
            kinds.append("configured_certificate_load_failed")
        elif "server could not load the certificate" in low:
            kinds.append("certificate_load_failed")
        elif "unable to initialize ssl encryption" in low:
            kinds.append("encryption_initialization_failed")
    return {
        "certificate_startup_log_classification": kinds[-1] if kinds else "not_observed_in_current_log",
        "certificate_startup_marker_observed": bool(kinds),
        "current_service_generation_verified": False,
        "actual_tls_certificate_verified": False,
        "tls_trust_chain_verified": False,
    }


def collect(expected_sha: str, correlation_id: str, registry: Any) -> dict[str, Any]:
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
        isinstance(x, dict) and x.get("instance") == "MSSQLSERVER"
        and x.get("service_state") == "running"
        and str(x.get("installed_version", "")).startswith("17.")
        for x in sql.get("instances", [])
    ):
        raise Blocked("local_sql2025_not_running")
    configured, argument_verified = registered_path(registry)
    raw = _safe_regular_file(Path(configured))
    result = classify_cert_log(decode_log(raw))
    return {
        "status": "observed", "schema": "noteri-sql-certificate-log-inventory/v1",
        "host": "Noteri", "source_sha": expected_sha, "correlation_id": correlation_id,
        "startup_log_argument_verified": argument_verified,
        "log_source": "registered_argument" if argument_verified else "unverified_setup_candidate",
        **result,
        "sql_authenticated": False, "business_data_read": False,
        "registry_modified": False, "production_touched": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        import winreg
        result = collect(args.expected_sha, args.correlation_id, winreg)
        code = 0
    except (Blocked, native.Blocked) as exc:
        message = str(exc)
        codes = {
            "noteri_windows_required", "source_sha_invalid", "source_sha_mismatch",
            "correlation_invalid", "normal_profile_required", "local_sql2025_not_running",
            "sql_install_path_invalid", "sql_startup_arguments_invalid",
            "sql_setup_path_absent", "sql_setup_path_denied",
            "sql_startup_parameters_absent", "sql_startup_parameters_denied",
            "sql_errorlog_file_absent", "sql_errorlog_file_denied",
            "sql_errorlog_argument_unverified", "sql_errorlog_path_not_allowlisted",
            "sql_instance_path_unverified", "errorlog_reparse_point",
            "errorlog_size_or_type_unverified", "errorlog_changed_during_read",
        }
        result = {"status": "blocked", "code": message if message in codes else "certificate_log_unavailable"}
        code = 2
    except Exception:
        result = {"status": "blocked", "code": "certificate_log_unavailable"}
        code = 2
    result.setdefault("sql_authenticated", False)
    result.setdefault("registry_modified", False)
    result.setdefault("production_touched", False)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
