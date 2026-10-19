"""Noteri native qualification: metadata only, no shell/secret/service mutation."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOST = "Noteri"
REPOSITORY = "ericson-j-santos/noteri-runtime"
INSTALL = Path(r"C:\dev\chatgpt-command-gateway")
MANAGED = frozenset((
    "bin/command_gateway.py", "bin/host_health_check.py",
    "bin/session_bootstrap.py", "bin/session_preflight.py",
    "bin/session_launcher.py", "bin/runner_version_preflight.py", "config/policy.json",
))
class Blocked(ValueError):
    pass

def read_regular(path: Path, limit: int = 1024 * 1024) -> bytes:
    # Refuse reparse points in every existing component, not only the leaf.
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise Blocked("reparse_path")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise Blocked("file_shape_or_limit")
    data = path.read_bytes()
    if len(data) != info.st_size:
        raise Blocked("file_changed")
    return data

def read_json(path: Path) -> dict:
    result = json.loads(read_regular(path).decode("utf-8-sig"))
    if not isinstance(result, dict):
        raise Blocked("json_object_required")
    return result

def rollback_readback(install: Path = INSTALL) -> dict:
    update_path = install / "update-receipt.json"
    if not update_path.exists():
        return {"status": "no_update_receipt", "matches_previous": None, "state_verified": None}
    update = read_json(update_path)
    backup = Path(str(update.get("backup_dir", "")))
    if backup.parent.resolve() != install.resolve() or not re.fullmatch(
            r"backup-[A-Za-z0-9-]+", backup.name):
        raise Blocked("rollback_location_invalid")
    raw = read_regular(backup / "rollback-manifest.json")
    snapshot = json.loads(raw)
    entries = snapshot.get("entries")
    if (snapshot.get("version") != 1 or not isinstance(entries, dict)
            or set(entries) != MANAGED
            or Path(snapshot.get("install_root", "")).resolve() != install.resolve()):
        raise Blocked("rollback_manifest_invalid")
    states = {}
    for rel, previous in entries.items():
        target = install / rel
        if previous.get("existed") is False:
            states[rel] = {"matches_previous": not target.exists()}
            continue
        if previous.get("existed") is not True:
            raise Blocked("rollback_entry_invalid")
        data = read_regular(target)
        saved = read_regular(backup / "files" / rel)
        digest = hashlib.sha256(data).hexdigest()
        backup_ok = (hashlib.sha256(saved).hexdigest() == previous.get("previous_sha256")
                     and len(saved) == previous.get("previous_size"))
        states[rel] = {
            "sha256": digest, "size": len(data),
            "matches_previous": backup_ok
            and digest == previous.get("previous_sha256")
            and len(data) == previous.get("previous_size")
            and stat.S_IMODE(target.stat().st_mode) == previous.get("previous_mode"),
        }
    matches_previous = all(row["matches_previous"] for row in states.values())
    update_result = update.get("result")
    state_verified = False
    if update_result == "HOST_UPDATE_BLOCKED":
        state_verified = matches_previous
    elif update_result == "HOST_UPDATE_OK":
        # Successful upgrades must match the desired bundle, not the old backup.
        declared = update.get("files")
        if isinstance(declared, dict) and set(declared) == MANAGED:
            state_verified = True
            for rel, entry in entries.items():
                current = read_regular(install / rel)
                desired = declared.get(rel)
                if (not isinstance(desired, dict)
                        or hashlib.sha256(current).hexdigest() != entry.get("desired_sha256")
                        or len(current) != entry.get("desired_size")
                        or desired.get("sha256") != entry.get("desired_sha256")
                        or desired.get("size") != entry.get("desired_size")):
                    state_verified = False
    return {"status": "observed", "matches_previous": matches_previous,
        "state_verified": state_verified, "update_result": update_result,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(), "files": states}

def service_state(name: str) -> str:
    from ctypes import wintypes
    class Status(ctypes.Structure):
        _fields_ = [(field, wintypes.DWORD) for field in (
            "service_type", "state", "controls", "win32_exit", "service_exit",
            "checkpoint", "wait_hint", "pid", "flags")]
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    dll.OpenSCManagerW.restype = wintypes.HANDLE
    dll.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    dll.OpenServiceW.restype = wintypes.HANDLE
    dll.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    dll.QueryServiceStatusEx.restype = wintypes.BOOL
    dll.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    scm = dll.OpenSCManagerW(None, None, 1)
    if not scm:
        raise Blocked("service_manager_read_denied")
    service = None
    try:
        service = dll.OpenServiceW(scm, name, 4)  # QUERY_STATUS, never START/STOP.
        if not service:
            if ctypes.get_last_error() == 1060:
                return "absent"
            raise Blocked("service_read_denied")
        state, needed = Status(), wintypes.DWORD()
        if not dll.QueryServiceStatusEx(service, 0, ctypes.byref(state),
                ctypes.sizeof(state), ctypes.byref(needed)):
            raise Blocked("service_status_unavailable")
        return {1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
                5: "continue_pending", 6: "pause_pending", 7: "paused"}.get(state.state, "unknown")
    finally:
        if service:
            dll.CloseServiceHandle(service)
        dll.CloseServiceHandle(scm)

def sql_inventory() -> dict:
    import winreg
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    key_path = r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    instances = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
            count = winreg.QueryInfoKey(key)[1]
            if count > 32:
                raise Blocked("sql_instance_limit")
            for i in range(count):
                name, instance, _ = winreg.EnumValue(key, i)
                if (not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", instance)):
                    raise Blocked("sql_registry_value_invalid")
                version = None
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            rf"SOFTWARE\Microsoft\Microsoft SQL Server\{instance}\Setup",
                            0, access) as setup:
                        candidate = str(winreg.QueryValueEx(setup, "Version")[0])
                        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", candidate):
                            version = candidate
                except FileNotFoundError:
                    pass
                service = "MSSQLSERVER" if name.upper() == "MSSQLSERVER" else "MSSQL$" + name
                instances.append({"instance": name, "installed_version": version,
                                  "service_state": service_state(service)})
    except FileNotFoundError:
        pass
    drivers = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers", 0, access) as key:
            for i in range(min(winreg.QueryInfoKey(key)[1], 128)):
                name, installed, _ = winreg.EnumValue(key, i)
                if re.fullmatch(r"ODBC Driver (17|18) for SQL Server", name) and installed == "Installed":
                    drivers.append(name)
    except FileNotFoundError:
        pass
    return {"status": "observed", "instances": instances, "odbc_drivers": sorted(drivers),
            "sql_connection_tested": False, "hml_verified": False}

def profile() -> dict:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise Blocked("localappdata_missing")
    path = Path(local) / "ReqSys" / "TodoGlobal24x7" / "host-profile.json"
    if not path.exists():
        return {"profile": None, "source": "missing", "verified": False}
    value = read_json(path)
    if value.get("profile") not in ("NORMAL", "ESTUDO") or (
            str(value.get("host", "")).casefold() != HOST.casefold()):
        raise Blocked("profile_identity_invalid")
    return {"profile": value["profile"], "source": "file", "verified": True}

def source_head(expected: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise Blocked("source_sha_invalid")
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                            text=True, timeout=15, check=False, shell=False)
    if result.returncode != 0 or result.stdout.strip() != expected:
        raise Blocked("source_sha_mismatch")
    return expected

def collect(expected_sha: str, correlation_id: str) -> dict:
    if os.name != "nt" or socket.gethostname().casefold() != HOST.casefold():
        raise Blocked("noteri_windows_required")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", correlation_id):
        raise Blocked("correlation_invalid")
    source_head(expected_sha)
    policy = read_json(INSTALL / "config" / "policy.json")
    return {"schema_version": "1", "status": "observed", "host": HOST,
            "source_sha": expected_sha, "correlation_id": correlation_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "python_executable_sha256": hashlib.sha256(read_regular(Path(sys.executable), 128*1024*1024)).hexdigest(),
            "installed_rules_version": policy.get("rules_version"),
            "rollback": rollback_readback(), "operating_profile": profile(),
            "sql": sql_inventory(), "hml_verified": False,
            "production_touched": False, "secrets_read": False, "mutations_executed": False}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    try:
        result = collect(args.source_sha, args.correlation_id)
        code = 0
    except Exception as exc:
        result = {"status": "blocked", "code": str(exc) if isinstance(exc, Blocked)
                  else type(exc).__name__, "hml_verified": False}
        code = 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return code

if __name__ == "__main__":
    raise SystemExit(main())
