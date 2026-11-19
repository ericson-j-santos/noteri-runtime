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

def _is_windows() -> bool:
    return os.name == "nt"


def _windows_metadata_helper():
    """Load only the already SHA-pinned Win32 metadata implementation.

    Missing checkout or mismatched bytes fail closed. Never use an arbitrary
    helper from PATH, PYTHONPATH or the active Gateway installation.
    """
    if not _is_windows():
        raise Blocked("windows_metadata_required")
    rules_root = os.environ.get("NOTERI_RULES_CHECKOUT")
    if not rules_root or not Path(rules_root).is_absolute():
        raise Blocked("windows_metadata_helper_unavailable")
    helper_path = Path(rules_root) / "_rules" / "scripts" / "install_command_gateway_host.py"
    try:
        import noteri_gateway_forensic_inventory as forensic
        return forensic._canonical_helper(helper_path)
    except Exception:
        raise Blocked("windows_metadata_helper_unverified") from None


def _windows_metadata_equal(helper, expected: dict, target: Path, rel: str) -> bool:
    try:
        helper._validate_windows_persisted_state(expected, rel)
        first = helper._windows_persisted_file_state(target)
        second = helper._windows_persisted_file_state(target)
        return (first == second
                and helper._windows_persisted_state_equivalent(expected, first))
    except Exception:
        raise Blocked("windows_metadata_unverified") from None


def rollback_readback(install: Path = INSTALL) -> dict:
    update_path = install / "update-receipt.json"
    if not update_path.exists():
        return {"status": "no_update_receipt", "matches_previous": None, "state_verified": None}
    receipt_before = read_regular(update_path)
    try:
        update = json.loads(receipt_before)
    except (UnicodeError, json.JSONDecodeError):
        raise Blocked("rollback_receipt_invalid") from None
    if not isinstance(update, dict):
        raise Blocked("rollback_receipt_invalid")
    backup = Path(str(update.get("backup_dir", "")))
    if backup.parent.resolve() != install.resolve() or not re.fullmatch(
            r"backup-[A-Za-z0-9-]+", backup.name):
        raise Blocked("rollback_location_invalid")
    raw = read_regular(backup / "rollback-manifest.json")
    try:
        snapshot = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise Blocked("rollback_manifest_invalid") from None
    entries = snapshot.get("entries") if isinstance(snapshot, dict) else None
    version = snapshot.get("version") if isinstance(snapshot, dict) else None
    if (version not in (1, 2) or type(version) is not int
            or not isinstance(entries, dict) or set(entries) != MANAGED
            or Path(str(snapshot.get("install_root", ""))).resolve() != install.resolve()):
        raise Blocked("rollback_manifest_invalid")
    if _is_windows() and version == 1:
        # v1 has no authenticated owner, DACL or alternate data streams.
        raise Blocked("windows_rollback_v1_unverifiable")
    helper = None
    if version == 2:
        if (not _is_windows()
                or snapshot.get("metadata_contract") != "windows-owner-group-dacl-ads-v1"):
            raise Blocked("rollback_metadata_contract_invalid")
        helper = _windows_metadata_helper()
    states = {}
    backup_integrity = True
    for rel, previous in entries.items():
        if not isinstance(previous, dict) or type(previous.get("existed")) is not bool:
            raise Blocked("rollback_entry_invalid")
        target = install / rel
        if version == 2:
            want_sha = previous.get("desired_sha256")
            want_size = previous.get("desired_size")
            source = previous.get("source")
            approved_sources = {
                "bin/command_gateway.py": "scripts/command_gateway.py",
                "bin/host_health_check.py": "scripts/host_health_check.py",
                "bin/session_bootstrap.py": "scripts/session_bootstrap.py",
                "bin/session_preflight.py": "scripts/session_preflight.py",
                "bin/session_launcher.py": "scripts/session_launcher.py",
                "bin/runner_version_preflight.py": "scripts/runner_version_preflight.py",
                "config/policy.json": ("config/command-gateway.policy.json",
                                       "config/command-gateway.policy.noteri-wsl.json"),
            }
            expected_sources = approved_sources.get(rel)
            if (expected_sources is None
                    or source not in ((expected_sources,) if isinstance(expected_sources, str)
                                      else expected_sources)
                    or not isinstance(want_sha, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", want_sha)
                    or type(want_size) is not int or want_size < 0):
                raise Blocked("rollback_entry_invalid")
        if previous["existed"] is False:
            if version == 2 and "previous_windows_state" in previous:
                raise Blocked("rollback_entry_invalid")
            if (backup / "files" / rel).exists() or (backup / "files" / rel).is_symlink():
                raise Blocked("unexpected_backup_for_new_file")
            states[rel] = {"matches_previous": not target.exists() and not target.is_symlink()}
            continue
        data = read_regular(target)
        saved_path = backup / "files" / rel
        saved = read_regular(saved_path)
        digest = hashlib.sha256(data).hexdigest()
        prior_sha = previous.get("previous_sha256")
        prior_size = previous.get("previous_size")
        prior_mode = previous.get("previous_mode")
        if (not isinstance(prior_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", prior_sha)
                or type(prior_size) is not int or prior_size < 0
                or type(prior_mode) is not int or prior_mode < 0):
            raise Blocked("rollback_entry_invalid")
        backup_ok = (hashlib.sha256(saved).hexdigest() == prior_sha
                     and len(saved) == prior_size
                     and stat.S_IMODE(saved_path.stat().st_mode) == prior_mode)
        metadata_ok = True
        saved_metadata_ok = True
        if version == 2:
            expected = previous.get("previous_windows_state")
            if not isinstance(expected, dict):
                raise Blocked("rollback_windows_metadata_missing")
            saved_metadata_ok = _windows_metadata_equal(helper, expected, saved_path, rel)
            metadata_ok = (saved_metadata_ok and
                           _windows_metadata_equal(helper, expected, target, rel))
        backup_integrity = backup_integrity and backup_ok and saved_metadata_ok
        states[rel] = {
            "sha256": digest, "size": len(data),
            "matches_previous": backup_ok and metadata_ok
            and digest == prior_sha and len(data) == prior_size
            and stat.S_IMODE(target.stat().st_mode) == prior_mode,
        }
    matches_previous = all(row["matches_previous"] for row in states.values())
    update_result = update.get("result")
    state_verified = False
    if update_result == "HOST_UPDATE_BLOCKED":
        state_verified = matches_previous
    elif update_result in ("HOST_UPDATE_OK", "HOST_UPDATE_ALREADY_CURRENT_VERIFIED"):
        declared = update.get("files")
        if isinstance(declared, dict) and set(declared) == MANAGED:
            state_verified = backup_integrity
            for rel, entry in entries.items():
                desired = declared.get(rel)
                if not isinstance(desired, dict):
                    state_verified = False
                    continue
                try:
                    current = read_regular(install / rel)
                except (OSError, Blocked):
                    state_verified = False
                    continue
                desired_sha = entry.get("desired_sha256")
                desired_size = entry.get("desired_size")
                if (not isinstance(desired_sha, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", desired_sha)
                        or type(desired_size) is not int or desired_size < 0
                        or hashlib.sha256(current).hexdigest() != desired_sha
                        or len(current) != desired_size
                        or desired.get("sha256") != desired_sha
                        or desired.get("size") != desired_size):
                    state_verified = False
                if version == 2 and entry.get("existed"):
                    # Metadata after installation must still match the
                    # previous secured ACL/ADS unless independently updated.
                    if not _windows_metadata_equal(
                            helper, entry["previous_windows_state"], install / rel, rel):
                        state_verified = False
    # Detect a replacement or concurrent update of the trusted evidence.
    if read_regular(update_path) != receipt_before:
        raise Blocked("rollback_receipt_changed")
    if read_regular(backup / "rollback-manifest.json") != raw:
        raise Blocked("rollback_manifest_changed")
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
