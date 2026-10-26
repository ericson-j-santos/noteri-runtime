"""Read-only HCS snapshot of EXISTING compute systems on Noteri Windows.

HcsEnumerateComputeSystems only; never asks WSL/Lxss to create an instance,
starts a process, attaches to a VM, or reads guest files.
HCS can reveal a *candidate* WSL VM, not which Ubuntu distro is running.
"""
from __future__ import annotations

import ctypes
import json
import socket
import sys

HOST = "noteri"
MAX_BYTES = 65536
MAX_SYSTEMS = 64
HCS_TIMEOUT_MS = 15_000
RUNNING_STATES = frozenset(("running",))


class Blocked(ValueError):
    """Fixed error categories; never pass OS error text or HCS JSON to logs."""


def _bind(dll, symbol: str, args, result):
    fn = getattr(dll, symbol)
    fn.argtypes = args
    fn.restype = result
    return fn


def enumerate_existing():
    """Use the documented read-only HCS enumeration API and bounded timeout."""
    if sys.platform != "win32":
        raise Blocked("NOT_WINDOWS")
    try:
        core = ctypes.WinDLL("ComputeCore.dll")
        kernel = ctypes.WinDLL("kernel32.dll")
        ptr = ctypes.c_void_p
        create = _bind(core, "HcsCreateOperation", [ptr, ptr], ptr)
        enumerate_ = _bind(core, "HcsEnumerateComputeSystems", [ctypes.c_wchar_p, ptr], ctypes.c_long)
        wait = _bind(core, "HcsWaitForOperationResult", [ptr, ctypes.c_uint32, ctypes.POINTER(ptr)], ctypes.c_long)
        close = _bind(core, "HcsCloseOperation", [ptr], None)
        local_free = _bind(kernel, "LocalFree", [ptr], ptr)
        operation = create(None, None)
        if not operation:
            raise Blocked("HCS_OPERATION_UNAVAILABLE")
        document = ptr()
        try:
            if enumerate_(None, operation) != 0:
                raise Blocked("HCS_ENUMERATION_REJECTED")
            # Microsoft's reference sample waits indefinitely. Keep this probe
            # bounded, but allow a cold HCS service enough time to enumerate
            # existing systems while staying below the Gateway's 30 s limit.
            if wait(operation, HCS_TIMEOUT_MS, ctypes.byref(document)) != 0:
                raise Blocked("HCS_ENUMERATION_UNAVAILABLE")
            if not document.value:
                raise Blocked("HCS_RESPONSE_EMPTY")
            # Avoid copying unbounded HCS data into Python or recording IDs/names.
            text = ctypes.wstring_at(document.value)
            if len(text.encode("utf-8")) > MAX_BYTES:
                raise Blocked("HCS_RESPONSE_LIMIT")
            return json.loads(text)
        finally:
            if document.value:
                local_free(document)
            close(operation)
    except Blocked:
        raise
    except (OSError, ValueError, AttributeError, OverflowError):
        raise Blocked("HCS_API_UNAVAILABLE") from None


def summarize(rows, *, platform_name=None, hostname=None):
    platform_name = sys.platform if platform_name is None else platform_name
    hostname = socket.gethostname() if hostname is None else hostname
    if platform_name != "win32" or type(hostname) is not str or hostname.casefold() != HOST:
        raise Blocked("NOTERI_WINDOWS_REQUIRED")
    if type(rows) is not list or len(rows) > MAX_SYSTEMS:
        raise Blocked("HCS_COLLECTION_INVALID")
    wsl_candidates = 0
    linux_vm_running = 0
    incomplete = 0
    for row in rows:
        if type(row) is not dict:
            raise Blocked("HCS_ROW_INVALID")
        # Only SystemType is mandatory in the HCS schema. Missing optional
        # metadata never proves readiness, and its absence is reported.
        typ = row.get("SystemType")
        if type(typ) is not str or not 0 < len(typ) <= 128:
            raise Blocked("HCS_FIELDS_INVALID")
        fields = []
        missing = False
        for key in ("RuntimeOsType", "State", "Owner"):
            value = row.get(key)
            if value is None:
                value, missing = "", True
            if type(value) is not str or len(value) > 128:
                raise Blocked("HCS_FIELDS_INVALID")
            fields.append(value)
        os_type, state, owner = fields
        if missing:
            incomplete += 1
        if typ.casefold() == "virtualmachine" and os_type.casefold() == "linux" and state.casefold() in RUNNING_STATES:
            linux_vm_running += 1
            if "wsl" in owner.casefold():
                wsl_candidates += 1
    return {
        "result": "NOTERI_HCS_READONLY_OBSERVED",
        "scope": "current_windows_identity_existing_compute_systems_only",
        "system_count": len(rows),
        "metadata_incomplete_count": incomplete,
        "linux_vm_running_count": linux_vm_running,
        "wsl_vm_running_candidate_count": wsl_candidates,
        "wsl_vm_candidate_observed": wsl_candidates > 0,
        "ubuntu_distro_running_verified": False,
        "posix_transport_verified": False,
        "systemd_verified": False,
        "postgresql_verified": False,
        "agent_qwen_autonomous_verified": False,
        "wsl_invoked": False,
        "guest_started": False,
        "service_started": False,
        "state_changed": False,
    }


def collect(*, platform_name=None, hostname=None, enumerator=None):
    platform_name = sys.platform if platform_name is None else platform_name
    hostname = socket.gethostname() if hostname is None else hostname
    if platform_name != "win32" or type(hostname) is not str or hostname.casefold() != HOST:
        raise Blocked("NOTERI_WINDOWS_REQUIRED")
    reader = enumerate_existing if enumerator is None else enumerator
    return summarize(reader(), platform_name=platform_name, hostname=hostname)


def main():
    try:
        if len(sys.argv) != 1:
            raise Blocked("ARGUMENTS_DENIED")
        print(json.dumps(collect(), sort_keys=True, separators=(",", ":")))
        return 0
    except (Blocked, OSError, ValueError) as exc:
        permitted = frozenset({
            "NOT_WINDOWS", "NOTERI_WINDOWS_REQUIRED", "ARGUMENTS_DENIED",
            "HCS_OPERATION_UNAVAILABLE", "HCS_ENUMERATION_REJECTED",
            "HCS_ENUMERATION_UNAVAILABLE", "HCS_RESPONSE_EMPTY",
            "HCS_RESPONSE_LIMIT", "HCS_API_UNAVAILABLE",
            "HCS_COLLECTION_INVALID", "HCS_ROW_INVALID", "HCS_FIELDS_INVALID",
        })
        code = str(exc) if isinstance(exc, Blocked) and str(exc) in permitted else "HCS_UNEXPECTED_FAILURE"
        print(json.dumps({"result": "NOTERI_HCS_READONLY_BLOCKED",
                          "reason": code,
                          "ubuntu_distro_running_verified": False,
                          "state_changed": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
