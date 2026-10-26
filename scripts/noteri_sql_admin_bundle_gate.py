#!/usr/bin/env python3
"""Fail-closed, read-only attestation of a proposed protected Noteri SQL admin bundle.

This is NOT an installer or an elevation mechanism. It must be invoked through
an already-authorized Session Launcher/Command Gateway before a privileged
control plane is considered for activation.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
from typing import Any, Callable, Mapping

SCHEMA = "noteri-sql-admin-protected-bundle/v1"
BUNDLE_ROOT = Path(r"C:\ProgramData\ReqSys\NoteriSqlAdminBroker")
FILES = frozenset({
    "noteri_sql_admin_errorlog_read.py",
    "noteri_sql_certificate_errorlog.py",
    "noteri_native_qualification.py",
    "noteri_sql_admin_bundle_gate.py",
})
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OWNER = re.compile(r"^O:(?:BA|SY)(?=G:|D:)")
ACE = re.compile(r"\([^()]+\)")
MAX_FILE_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 8 * 1024
ACL_READ_FLAGS = 0x1 | 0x4   # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
SE_FILE_OBJECT = 1


class Blocked(RuntimeError):
    """Constant, non-sensitive failure code."""


def validate_sddl(sddl: Any, *, protected: bool) -> None:
    """Require explicit SYSTEM/Administrators only; no inherited broad access."""
    if not isinstance(sddl, str) or not OWNER.match(sddl) or sddl.count("D:") != 1:
        raise Blocked("admin_acl_owner_or_dacl_unverified")
    dacl = sddl.split("D:", 1)[1]
    if "S:" in dacl:
        raise Blocked("admin_acl_unexpected_section")
    prefix = dacl.split("(", 1)[0]
    if not re.fullmatch(r"[PAI]*", prefix) or (protected and "P" not in prefix):
        raise Blocked("admin_acl_not_protected")
    aces = ACE.findall(dacl)
    if not aces or prefix + "".join(aces) != dacl:
        raise Blocked("admin_acl_entries_unverified")
    principals: set[str] = set()
    for item in aces:
        parts = item[1:-1].split(";")
        if len(parts) != 6 or parts[0] != "A" or parts[5] not in {"SY", "BA"}:
            raise Blocked("admin_acl_writable_principal_unverified")
        if parts[2].upper() not in {"FA", "0X1F01FF", "0X001F01FF"}:
            raise Blocked("admin_acl_rights_unverified")
        if not re.fullmatch(r"(?:OI|CI|ID|IO|NP)*", parts[1]):
            raise Blocked("admin_acl_flags_unverified")
        principals.add(parts[5])
    if principals != {"SY", "BA"}:
        raise Blocked("admin_acl_principal_missing")


def validate_manifest(manifest: Any, files: Mapping[str, bytes], expected_sha: str) -> None:
    if not isinstance(expected_sha, str) or not SHA40.fullmatch(expected_sha):
        raise Blocked("source_sha_invalid")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "host", "environment", "capability", "source_sha", "files",
    }:
        raise Blocked("admin_manifest_schema_invalid")
    if (
        manifest["schema"] != SCHEMA or manifest["host"] != "Noteri"
        or manifest["environment"] != "dev"
        or manifest["capability"] != "sql-errorlog-readonly"
        or manifest["source_sha"] != expected_sha
    ):
        raise Blocked("admin_manifest_binding_invalid")
    checksums = manifest["files"]
    if not isinstance(checksums, dict) or set(checksums) != FILES or set(files) != FILES:
        raise Blocked("admin_manifest_file_set_invalid")
    for filename, value in checksums.items():
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise Blocked("admin_manifest_digest_invalid")
        data = files[filename]
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_BYTES:
            raise Blocked("admin_bundle_file_invalid")
        if hashlib.sha256(data).hexdigest() != value:
            raise Blocked("admin_bundle_integrity_mismatch")


def _descriptor(path: Path) -> str:
    """Read Windows owner and DACL by Win32 API; do not expose SID/path values."""
    if os.name != "nt":
        raise Blocked("windows_acl_required")
    sd = ctypes.c_void_p()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    text_ptr = ctypes.c_wchar_p()
    try:
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        get_security = api.GetNamedSecurityInfoW
        get_security.argtypes = [
            wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        get_security.restype = wintypes.DWORD
        to_sddl = api.ConvertSecurityDescriptorToStringSecurityDescriptorW
        to_sddl.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p,
        ]
        to_sddl.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        if get_security(str(path), SE_FILE_OBJECT, ACL_READ_FLAGS,
                        ctypes.byref(owner), None, ctypes.byref(dacl),
                        None, ctypes.byref(sd)) != 0:
            raise Blocked("admin_acl_unreadable")
        if not to_sddl(sd, 1, ACL_READ_FLAGS, ctypes.byref(text_ptr), None):
            raise Blocked("admin_acl_unreadable")
        return ctypes.wstring_at(text_ptr)
    except (OSError, AttributeError, TypeError, ValueError) as exc:
        raise Blocked("admin_acl_unreadable") from None
    finally:
        if os.name == "nt":
            try:
                k = ctypes.WinDLL("kernel32", use_last_error=True)
                k.LocalFree.argtypes = [ctypes.c_void_p]
                k.LocalFree.restype = ctypes.c_void_p
                if text_ptr:
                    k.LocalFree(ctypes.cast(text_ptr, ctypes.c_void_p))
                if sd:
                    k.LocalFree(sd)
            except (OSError, AttributeError):
                pass


def _regular(path: Path, max_bytes: int) -> bytes:
    try:
        meta = path.lstat()
        if (not stat.S_ISREG(meta.st_mode) or meta.st_size <= 0 or
            meta.st_size > max_bytes or
            getattr(meta, "st_file_attributes", 0) & 0x400):
            raise Blocked("admin_file_not_regular")
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
        if len(data) != meta.st_size or after.st_size != meta.st_size:
            raise Blocked("admin_file_changed_during_read")
        return data
    except OSError:
        raise Blocked("admin_file_unavailable") from None


def _directory(path: Path) -> None:
    try:
        meta = path.lstat()
        if not stat.S_ISDIR(meta.st_mode) or getattr(meta, "st_file_attributes", 0) & 0x400:
            raise Blocked("admin_directory_untrusted")
    except OSError:
        raise Blocked("admin_directory_unavailable") from None


def attest(expected_sha: str, *, host: str | None = None,
           platform: str | None = None,
           descriptor: Callable[[Path], str] = _descriptor) -> dict[str, Any]:
    """Read only a fixed protected ProgramData tree, never install/elevate."""
    if (os.name if platform is None else platform) != "nt" or (
        socket.gethostname() if host is None else host
    ).casefold() != "noteri":
        raise Blocked("noteri_windows_required")
    if not isinstance(expected_sha, str) or not SHA40.fullmatch(expected_sha):
        raise Blocked("source_sha_invalid")
    if os.environ.get("ProgramData", "").casefold() != r"c:\programdata":
        raise Blocked("programdata_location_unverified")

    parent = BUNDLE_ROOT.parent
    binaries = BUNDLE_ROOT / "bin"
    for path in (Path(r"C:\ProgramData"), parent, BUNDLE_ROOT, binaries):
        _directory(path)
    for path in (parent, BUNDLE_ROOT, binaries):
        validate_sddl(descriptor(path), protected=(path != binaries))

    manifest_path = BUNDLE_ROOT / "manifest.json"
    validate_sddl(descriptor(manifest_path), protected=False)
    raw = _regular(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Blocked("admin_manifest_unreadable") from None
    bundle: dict[str, bytes] = {}
    for name in sorted(FILES):
        path = binaries / name
        validate_sddl(descriptor(path), protected=False)
        bundle[name] = _regular(path, MAX_FILE_BYTES)
    validate_manifest(manifest, bundle, expected_sha)
    return {
        "status": "ready", "schema": SCHEMA, "host": "Noteri",
        "environment": "dev", "source_sha": expected_sha,
        "acl_verified": True, "bundle_integrity_verified": True,
        "elevated_execution_performed": False, "sql_read_performed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args(argv)
    try:
        response = attest(args.expected_sha)
        result = 0
    except Blocked as exc:
        response = {"status": "blocked", "code": str(exc), "schema": SCHEMA}
        result = 2
    except Exception:
        response = {"status": "blocked", "code": "admin_bundle_unavailable", "schema": SCHEMA}
        result = 2
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
