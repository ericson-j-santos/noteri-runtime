#!/usr/bin/env python3
"""Identify the existing Noteri Worker Pool port 8097 without credentials.

GET /health only, no auth tokens, no process control, no configuration changes,
no proxy and no redirects. Identifies the TCP PID using native Windows table.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import socket
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import source_sha
from noteri_ollama_http_owner_probe import identify_pids, RejectRedirect

PORT = 8097
URL = "http://127.0.0.1:8097/health"
CONFIRM = "AUDIT-NOTERI-POOL-PORT8097-READONLY"
HEAD = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
MAX_RESPONSE = 32 * 1024
MAX_TABLE = 1024 * 1024


class Blocked(ValueError):
    pass


def port_owner_pids(payload: bytes) -> list[int]:
    if not 4 <= len(payload) <= MAX_TABLE:
        raise Blocked("TCP_TABLE_SIZE_INVALID")
    count = struct.unpack_from("<I", payload, 0)[0]
    if count > (MAX_TABLE - 4) // 24 or 4 + count * 24 > len(payload):
        raise Blocked("TCP_TABLE_ROWS_INVALID")
    owners: list[int] = []
    for i in range(count):
        state, _local, port, _remote, _remote_port, pid = struct.unpack_from(
            "<6I", payload, 4 + 24 * i)
        if state == 2 and socket.ntohs(port & 0xffff) == PORT:
            if pid <= 0:
                raise Blocked("LISTENER_PID_UNAVAILABLE")
            owners.append(pid)
    return sorted(set(owners))


def windows_owners() -> list[dict[str, Any]]:
    if os.name != "nt":
        raise Blocked("NOT_WINDOWS")
    try:
        method = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
        method.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool,
            ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        method.restype = ctypes.c_ulong
        size = ctypes.c_ulong(0)
        if method(None, ctypes.byref(size), False, 2, 5, 0) != 122:
            raise Blocked("TCP_TABLE_UNAVAILABLE")
        if not 4 <= size.value <= MAX_TABLE:
            raise Blocked("TCP_TABLE_SIZE_INVALID")
        buffer = ctypes.create_string_buffer(size.value)
        if method(buffer, ctypes.byref(size), False, 2, 5, 0) != 0:
            raise Blocked("TCP_TABLE_UNAVAILABLE")
        return identify_pids(port_owner_pids(buffer.raw[:size.value]))
    except (OSError, AttributeError, ValueError, struct.error) as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("TCP_OWNER_UNAVAILABLE") from None


def probe_health() -> dict[str, Any]:
    request = urllib.request.Request(
        URL, method="GET", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), RejectRedirect())
    try:
        with opener.open(request, timeout=6) as response:
            status = response.status
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        raw = error.read(MAX_RESPONSE + 1)
    except (OSError, ValueError, UnicodeError, urllib.error.URLError):
        return {"result": "HTTP_NOT_ATTESTED"}
    if (status not in (200, 503) or not 0 < len(raw) <= MAX_RESPONSE):
        return {"result": "HTTP_UNEXPECTED", "http_status": status}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        return {"result": "HTTP_NOT_JSON", "http_status": status}
    if type(data) is not dict:
        return {"result": "HTTP_SCHEMA_INVALID", "http_status": status}
    if (data.get("service") != "codex-worker-pool"
            or data.get("status") not in ("healthy", "not_ready")
            or type(data.get("auth_configured")) is not bool
            or type(data.get("expected_rules_sha_configured")) is not bool):
        return {"result": "UNRECOGNIZED_SERVICE", "http_status": status}
    result = "WORKER_POOL_API_HEALTHY" if status == 200 and data["status"] == "healthy" else "WORKER_POOL_API_NOT_READY"
    return {
        "result": result, "http_status": status,
        "service": data["service"], "api_status": data["status"],
        "auth_configured": data["auth_configured"],
        "rules_pin_configured": data["expected_rules_sha_configured"],
        "storage_backend": data.get("storage_backend")
        if data.get("storage_backend") in ("sqlite", "postgres") else "UNKNOWN",
        "contract_version": str(data.get("contract_version", ""))[:50],
        # Never emit authority_id, raw response, private token, DB path, or logs.
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    a = parser.parse_args()
    try:
        if (not HEAD.fullmatch(a.expected_head)
                or not CORRELATION.fullmatch(a.correlation_id)
                or a.confirm != CONFIRM
                or os.name != "nt" or socket.gethostname().casefold() != "noteri"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != a.expected_head):
            raise Blocked("SOURCE_OR_HOST_NOT_ATTESTED")
        owners = windows_owners()
        health = probe_health()
        result = {
            "result": "WORKER_POOL_PORT8097_READONLY",
            "health": health, "owners": owners,
            "single_owner": len(owners) == 1,
            "service_identified": (
                len(owners) == 1
                and health.get("result") in (
                    "WORKER_POOL_API_HEALTHY", "WORKER_POOL_API_NOT_READY")),
            "state_changed": False, "credentials_read": False,
            "processes_started": False, "processes_stopped": False,
            "source_sha": a.expected_head, "correlation_id": a.correlation_id,
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    except Blocked as exc:
        print(json.dumps({"result": "WORKER_POOL_PORT8097_BLOCKED",
                          "reason": str(exc), "state_changed": False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
