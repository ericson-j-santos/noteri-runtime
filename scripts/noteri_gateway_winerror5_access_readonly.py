#!/usr/bin/env python3
"""Read-only Win32 access probe for the pinned failed Noteri Gateway transaction.

CreateFileW opens EXISTING files/directories for DELETE / FILE_DELETE_CHILD
*access only*; never calls DeleteFile, MoveFileEx, WriteFile or ACL setters.
A successful probe does not make a future update safe. A sharing violation
(32) is evidence of a conflicting handle at inspection time.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat

import noteri_gateway_journal_windows_metadata_readonly as metadata
import noteri_gateway_update_6f1_failure_readonly as failure
from noteri_ollama_recovery_preflight import source_sha

ROOT = Path(r"C:\dev\chatgpt-command-gateway")
TARGET = ROOT / "bin" / "session_preflight.py"
PARENT = ROOT / "bin"
CONFIRM = "PROBE-NOTERI-6F1-FAILED-DESTINATION-READONLY"
HEAD = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")

FILE_READ_ATTRIBUTES = 0x80
DELETE = 0x00010000
READ_CONTROL = 0x00020000
FILE_DELETE_CHILD = 0x40
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
ERROR_ACCESS_DENIED = 5
ERROR_SHARING_VIOLATION = 32
INVALID_HANDLE = ctypes.c_void_p(-1).value


class Blocked(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise Blocked(code)


def file_identity(path: Path):
    st = os.lstat(path)
    require(stat.S_ISREG(st.st_mode), "DESTINATION_NOT_REGULAR")
    require(not bool(getattr(st, "st_file_attributes", 0) & 0x400),
            "DESTINATION_REPARSE_POINT")
    raw = path.read_bytes()
    require(len(raw) == st.st_size and
            os.lstat(path).st_mtime_ns == st.st_mtime_ns,
            "DESTINATION_CHANGED_ON_READ")
    return {"sha256": hashlib.sha256(raw).hexdigest(),
            "device": st.st_dev, "inode": st.st_ino,
            "attributes": getattr(st, "st_file_attributes", 0),
            "size": st.st_size}


def probe_existing(path: Path, desired_access: int, *, directory=False,
                   kernel=None) -> dict:
    """Win32 OPEN_EXISTING + no-op close. No file content or metadata writes."""
    require(os.name == "nt", "WINDOWS_ONLY")
    k = kernel or ctypes.WinDLL("kernel32", use_last_error=True)
    open_ = k.CreateFileW
    open_.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                      ctypes.c_uint32, ctypes.c_void_p,
                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    open_.restype = ctypes.c_void_p
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    h = open_(str(path), desired_access, FILE_SHARE_ALL, None, OPEN_EXISTING,
              flags, None)
    if h is None or h == INVALID_HANDLE:
        error = ctypes.get_last_error()
        return {
            "granted": False,
            "winerror": int(error),
            "interpretation": (
                "SHARING_VIOLATION" if error == ERROR_SHARING_VIOLATION
                else "ACCESS_DENIED" if error == ERROR_ACCESS_DENIED
                else "OTHER_WIN32_ERROR"
            ),
        }
    try:
        return {"granted": True, "winerror": 0,
                "interpretation": "OPEN_GRANTED_AT_PROBE_TIME"}
    finally:
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle(ctypes.c_void_p(h))


def inspect(*, probe=probe_existing):
    require(os.name == "nt" and socket.gethostname().casefold() == "noteri",
            "NOTERI_WINDOWS_REQUIRED")
    require(ROOT.is_dir() and PARENT.is_dir(), "INSTALL_ROOT_INVALID")
    before_failure = failure.inspect()  # independent pinned rollback evidence
    require(before_failure["result"] == "NOTERI_GATEWAY_6F1_ROLLBACK_READBACK_OK"
            and before_failure["journal_present"] is True
            and before_failure["failure_winerror"] == 5
            and before_failure["failure_destination"] == "bin/session_preflight.py"
            and before_failure["installed_previous_state_files_verified"] == 7,
            "FAILED_ROLLBACK_EVIDENCE_DRIFT")
    with metadata.existing_exclusive_update_lock(ROOT):
        before = file_identity(TARGET)
        flags = before["attributes"]
        require(not bool(flags & 0x400), "REPARSE_POINT_DENIED")
        # No mutations are performed. Opening with DELETE *requests access*;
        # it cannot delete a file without a separate delete/rename call.
        probes = {
            "file_read_attributes": probe(TARGET, FILE_READ_ATTRIBUTES),
            "file_read_control": probe(TARGET, READ_CONTROL),
            "file_delete_access": probe(TARGET, DELETE),
            "directory_read_attributes": probe(PARENT, FILE_READ_ATTRIBUTES,
                                               directory=True),
            "directory_delete_child_access": probe(PARENT, FILE_DELETE_CHILD,
                                                   directory=True),
        }
        after = file_identity(TARGET)
        require(before == after, "FILE_CHANGED_DURING_ACCESS_PROBE")
        require((ROOT / "update-transaction.json").is_file(),
                "INCIDENT_JOURNAL_DISAPPEARED")
        require(failure.sha(ROOT / "update-transaction.json")
                == before_failure["transaction_journal_sha256"],
                "INCIDENT_JOURNAL_CHANGED")
        require(failure.sha(ROOT / "update-receipt.json")
                == before_failure["primary_receipt_sha256"],
                "PRIMARY_RECEIPT_CHANGED")
        return {
            "result": "NOTERI_6F1_DESTINATION_WIN32_ACCESS_READONLY",
            "host": "Noteri",
            "environment": "DEV",
            "target_commit": failure.TARGET,
            "journal_sha256": before_failure["transaction_journal_sha256"],
            "file_sha256": before["sha256"],
            "file_readonly_attribute": bool(flags & 0x1),
            "file_reparse_attribute": bool(flags & 0x400),
            "probes": probes,
            "original_update_winerror": 5,
            "file_content_unchanged": True,
            "update_lock_held": True,
            "mutation_performed": False,
            "root_cause_determined": (
                probes["file_delete_access"]["winerror"]
                == ERROR_SHARING_VIOLATION
            ),
            "interpretation_limit": (
                "Success is point-in-time only; error 5 cannot distinguish "
                "ACL/token/filter-driver/other protection from this probe"
            ),
        }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--confirm", required=True)
    n = p.parse_args()
    try:
        require(bool(HEAD.fullmatch(n.expected_head)) and
                bool(ID.fullmatch(n.correlation_id)) and
                n.confirm == CONFIRM and
                source_sha(Path(__file__).resolve().parents[1]) == n.expected_head,
                "REQUEST_SHA_OR_CONFIRM_INVALID")
        report = inspect()
        report["correlation_id"] = n.correlation_id
        print(json.dumps(report, sort_keys=True))
        return 0
    except (Blocked, metadata.Blocked, failure.ReadbackBlocked,
            OSError, ValueError) as exc:
        reason = (str(exc) if isinstance(
            exc, (Blocked, metadata.Blocked, failure.ReadbackBlocked))
            else "ACCESS_PROBE_UNAVAILABLE")
        print(json.dumps({
            "result": "NOTERI_6F1_ACCESS_PROBE_BLOCKED",
            "reason": reason, "mutation_performed": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
