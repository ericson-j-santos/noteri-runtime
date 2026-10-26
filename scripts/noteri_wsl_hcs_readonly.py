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
            if wait(operation, 3000, ctypes.byref(document)) != 0:
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
    for row in rows:
        if type(row) is not dict:
            raise Blocked("HCS_ROW_INVALID")
        # Unknown schema/key, owner, or state must fail closed: HCS is shared by
        # WSL, containers and other virtual machines on the same Windows host.
        typ = row.get("SystemType")
        os_type = row.get("RuntimeOsType")
        state = row.get("State")
        owner = row.get("Owner")
        if any(type(value) is not str or len(value) > 128 for value in (typ, os_type, state, owner)):
            raise Blocked("HCS_FIELDS_INVALID")
        if typ.casefold() == "virtualmachine" and os_type.casefold() == "linux" and state.casefold() in RUNNING_STATES:
            linux_vm_running += 1
            if "wsl" in owner.casefold():
                wsl_candidates += 1
    return {
        "result": "NOTERI_HCS_READONLY_OBSERVED",
        "scope": "current_windows_identity_existing_compute_systems_only",
        "system_count": len(rows),
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
    except (Blocked, OSError, ValueError):
        print(json.dumps({"result": "NOTERI_HCS_READONLY_BLOCKED",
                          "ubuntu_distro_running_verified": False,
                          "state_changed": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
