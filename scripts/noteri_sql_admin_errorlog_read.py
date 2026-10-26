#!/usr/bin/env python3
"""Administrative, read-only SQL 2025 startup ERRORLOG classification on Noteri DEV.

This is a *staged capability*, not an elevation or deployment mechanism.
An independently authorized, integrity-checked control plane must invoke it.
The confirmation string is an input guard, not proof of owner authorization.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import socket
from typing import Any, Callable

import noteri_sql_certificate_errorlog as certificate_log

CAPABILITY = "sql-errorlog-readonly"
CONFIRM = "READ-NOTERI-SQL-ERRORLOG-DEV"
OUTPUT_SCHEMA = "noteri-sql-admin-errorlog-read/v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{8,128}\Z")
CLASSIFICATIONS = frozenset({
    "self_generated_loaded", "store_certificate_loaded",
    "configured_certificate_load_failed", "certificate_load_failed",
    "encryption_initialization_failed", "not_observed_in_current_log",
})
REQUIRED_COLLECTOR_KEYS = frozenset({
    "status", "schema", "host", "source_sha", "correlation_id",
    "startup_log_argument_verified", "log_source",
    "certificate_startup_log_classification", "certificate_startup_marker_observed",
    "current_service_generation_verified", "actual_tls_certificate_verified",
    "tls_trust_chain_verified", "sql_authenticated", "business_data_read",
    "registry_modified", "production_touched",
})


class Blocked(ValueError):
    """Fixed, non-sensitive cause of a refused read."""


def is_elevated() -> bool:
    """Require an already privileged Windows process; never elevate here."""
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def require_preconditions(
    *, expected_sha: str, correlation_id: str, environment: str, confirmation: str,
    host: str, platform: str, admin_check: Callable[[], bool],
) -> None:
    if platform != "nt" or host.casefold() != "noteri":
        raise Blocked("noteri_windows_required")
    if environment != "dev":
        raise Blocked("dev_environment_required")
    if confirmation != CONFIRM:
        raise Blocked("confirmation_invalid")
    if not isinstance(expected_sha, str) or SHA40.fullmatch(expected_sha) is None:
        raise Blocked("source_sha_invalid")
    if not isinstance(correlation_id, str) or SAFE_ID.fullmatch(correlation_id) is None:
        raise Blocked("correlation_id_invalid")
    if admin_check() is not True:
        raise Blocked("admin_identity_required")


def _sanitize(value: Any, *, expected_sha: str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUIRED_COLLECTOR_KEYS:
        raise Blocked("collector_contract_invalid")
    if (
        value["status"] != "observed"
        or value["schema"] != "noteri-sql-certificate-log-inventory/v1"
        or value["host"] != "Noteri"
        or value["source_sha"] != expected_sha
        or value["correlation_id"] != correlation_id
        or value["startup_log_argument_verified"] is not True
        or value["log_source"] != "registered_argument"
    ):
        raise Blocked("active_startup_argument_unverified")
    classification = value["certificate_startup_log_classification"]
    if classification not in CLASSIFICATIONS:
        raise Blocked("certificate_classification_invalid")
    if type(value["certificate_startup_marker_observed"]) is not bool or (
        value["certificate_startup_marker_observed"]
        != (classification != "not_observed_in_current_log")
    ):
        raise Blocked("certificate_marker_inconsistent")
    for key in (
        "current_service_generation_verified", "actual_tls_certificate_verified",
        "tls_trust_chain_verified", "sql_authenticated", "business_data_read",
        "registry_modified", "production_touched",
    ):
        if value[key] is not False:
            raise Blocked("collector_security_contract_invalid")
    return {
        "status": "observed", "schema": OUTPUT_SCHEMA, "capability": CAPABILITY,
        "host": "Noteri", "environment": "dev", "source_sha": expected_sha,
        "correlation_id": correlation_id, "startup_log_argument_verified": True,
        "certificate_startup_log_classification": classification,
        "certificate_startup_marker_observed": value["certificate_startup_marker_observed"],
        "current_service_generation_verified": False,
        "actual_tls_certificate_verified": False, "tls_trust_chain_verified": False,
        "sql_authenticated": False, "business_data_read": False,
        "registry_modified": False, "production_touched": False,
    }


def collect(
    expected_sha: str, correlation_id: str, *, environment: str,
    confirmation: str, registry: Any, host: str | None = None,
    platform: str | None = None, admin_check: Callable[[], bool] = is_elevated,
    reader: Callable[[str, str, Any], dict[str, Any]] = certificate_log.collect,
) -> dict[str, Any]:
    """Read the one fixed SQL instance, enforcing verified -e and sanitized output."""
    require_preconditions(
        expected_sha=expected_sha, correlation_id=correlation_id,
        environment=environment, confirmation=confirmation,
        host=socket.gethostname() if host is None else host,
        platform=os.name if platform is None else platform,
        admin_check=admin_check,
    )
    # The existing reader enforces the MSSQL17.MSSQLSERVER path, NORMAL profile,
    # running SQL 2025 instance, source SHA, reparse-point and bounded file size.
    return _sanitize(reader(expected_sha, correlation_id, registry),
                     expected_sha=expected_sha, correlation_id=correlation_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--environment", required=True, choices=["dev"])
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    try:
        # No supplied executable, SQL, registry key, path or output destination.
        require_preconditions(
            expected_sha=args.expected_sha, correlation_id=args.correlation_id,
            environment=args.environment, confirmation=args.confirm,
            host=socket.gethostname(), platform=os.name, admin_check=is_elevated,
        )
        import winreg  # type: ignore[import-not-found]

        outcome = collect(
            args.expected_sha, args.correlation_id, environment=args.environment,
            confirmation=args.confirm, registry=winreg,
        )
        code = 0
    except Blocked as exc:
        outcome = {"status": "blocked", "code": str(exc), "schema": OUTPUT_SCHEMA}
        code = 2
    except Exception:
        # Windows registry/file errors and third-party messages may leak paths.
        outcome = {"status": "blocked", "code": "admin_errorlog_unavailable", "schema": OUTPUT_SCHEMA}
        code = 2
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
