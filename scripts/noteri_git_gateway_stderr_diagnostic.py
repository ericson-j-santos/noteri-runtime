#!/usr/bin/env python3
"""Read-only classification of the exact six Git probes used by Command Gateway.

Fixed Noteri DEV worktrees; no user-supplied path, shell or raw stderr output.
This does not authorize an execution after a Gateway denial.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess

EXPECTED_HEAD = "9840ec316ba5d76f17cd1cf113d208ed649daf7d"
ROOT = Path(r"C:\dev\chatgpt-workers")
TARGETS = (
    "wt-chat-noteri-six-pspath-9840-20261115",
    "wt-chat-noteri-six-pspath-fresh-9840-20261115",
)
CONFIRM = "NOTERI-GIT-STATE-SIX-READONLY-V1"
COMMANDS = (
    ("revparse_root", ("git", "rev-parse", "--show-toplevel")),
    ("revparse_head", ("git", "rev-parse", "HEAD")),
    ("current_branch", ("git", "branch", "--show-current")),
    ("tracked_status", ("git", "status", "--porcelain=v1", "-z", "--untracked-files=no")),
    ("index", ("git", "ls-files", "-s", "-z")),
    ("untracked", ("git", "ls-files", "--others", "--exclude-standard", "-z", "--", ".")),
    ("modified", ("git", "ls-files", "-m", "-d", "-z")),
)
SHA = re.compile(r"[0-9a-f]{40}\Z")


class Blocked(RuntimeError):
    pass


def classify_stderr(stderr: str) -> str:
    """Only stable categories, never raw stderr, paths or secrets."""
    if not stderr.strip():
        return "none"
    lowered = stderr.casefold()
    if "dubious ownership" in lowered or "safe.directory" in lowered:
        return "ownership"
    if "permission denied" in lowered or "access is denied" in lowered:
        return "access_denied"
    if "index.lock" in lowered or "unable to create" in lowered:
        return "lock_or_write"
    if "fsmonitor" in lowered:
        return "fsmonitor"
    if "unable to" in lowered or "could not" in lowered:
        return "filesystem"
    if lowered.lstrip().startswith("warning:"):
        return "warning_other"
    if lowered.lstrip().startswith("fatal:"):
        return "fatal_other"
    return "stderr_other"


def error_details(stderr: str) -> dict:
    """Classify known Git warnings; never disclose user-controlled error text."""
    lower = stderr.casefold()
    patterns = (
        ("unreadable_directory", "could not open directory"),
        ("excluded_directory", "unable to access"),
        ("unreadable_file", "failed to read"),
        ("permission", "permission denied"),
        ("not_found", "no such file or directory"),
        ("short_filename", "filename too long"),
    )
    return {
        "message_code": next((key for key, needle in patterns if needle in lower),
                             "UNCLASSIFIED"),
        "permission_denied": "permission denied" in lower
                             or "access is denied" in lower,
        "has_quoted_target": bool(re.search(r"['\"][^'\"]+['\"]", stderr)),
        "has_warning_prefix": lower.lstrip().startswith("warning:"),
    }


def isolate_untracked_warning(root: Path) -> list[dict]:
    """Retest with *fixed* tracked top-level pathspecs for location classification."""
    result = []
    for name in (".github", ".sdd", "docs", "scripts", "tests"):
        cmd = ("git", "ls-files", "--others", "--exclude-standard",
               "-z", "--", name)
        try:
            check = subprocess.run(
                cmd, cwd=root, text=True, capture_output=True,
                encoding="utf-8", errors="replace", timeout=20,
                check=False, shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            result.append({"area": name, "result": "EXECUTION_ERROR"})
            continue
        result.append({
            "area": name,
            "returncode": check.returncode,
            "stderr_type": classify_stderr(check.stderr or ""),
            "stderr_code": error_details(check.stderr or "")["message_code"],
            "stderr_sha256": hashlib.sha256(check.stderr.encode()).hexdigest()
                             if check.stderr else None,
        })
    return result


def probe(root: Path, expected_head: str) -> dict:
    """Read command results without exposing stdout or stderr contents."""
    if not SHA.fullmatch(expected_head):
        raise Blocked("HEAD_INVALID")
    if root.is_symlink() or not root.is_dir():
        raise Blocked("WORKTREE_UNAVAILABLE")
    steps = []
    for name, command in COMMANDS:
        try:
            done = subprocess.run(
                command, cwd=root, shell=False, text=True,
                capture_output=True, encoding="utf-8", errors="replace",
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            steps.append({"step": name, "status": "EXECUTION_ERROR"})
            break
        stderr = done.stderr or ""
        detail = {
            "step": name,
            "returncode": done.returncode,
            "stderr_type": classify_stderr(stderr),
            "stderr_length": len(stderr),
            "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()
                             if stderr else None,
        }
        if name == "revparse_root" and os.path.normcase(
            os.path.normpath(done.stdout.strip())
        ) != os.path.normcase(os.path.normpath(str(root))):
            detail["identity"] = "ROOT_MISMATCH"
        if name == "revparse_head" and done.stdout.strip().lower() != expected_head:
            detail["identity"] = "HEAD_MISMATCH"
        detail.update(error_details(stderr))
        steps.append(detail)
        if done.returncode != 0 or stderr.strip() or detail.get("identity"):
            break
    return {
        "status": "GIT_STATE_COMMANDS_CLEAN" if len(steps) == len(COMMANDS)
                  and not steps[-1].get("identity") else "GIT_STATE_COMMAND_BLOCKED",
        "steps": steps,
        "untracked_areas": isolate_untracked_warning(root) if steps[-1]["step"] == "untracked" and (steps[-1].get("stderr_type") != "none" or steps[-1].get("returncode") != 0) else [],
        "first_blocked": next((s["step"] for s in steps if
                               s.get("returncode") != 0
                               or s.get("stderr_type") not in (None, "none")
                               or s.get("identity")), None),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    if (os.name != "nt" or socket.gethostname().casefold() != "noteri"
            or args.confirm != CONFIRM or args.expected_head != EXPECTED_HEAD
            or not re.fullmatch(r"[A-Za-z0-9._:-]{12,128}", args.correlation_id)):
        print(json.dumps({"status": "BLOCKED_HOST_OR_IDENTITY"}))
        return 2
    result = []
    for name in TARGETS:
        root = ROOT / name
        try:
            if root.resolve(strict=True).parent != ROOT.resolve(strict=True):
                raise Blocked("OUTSIDE_FIXED_ROOT")
            current = probe(root, EXPECTED_HEAD)
            result.append({"target": name, **current})
        except (Blocked, OSError):
            result.append({"target": name, "status": "TARGET_UNAVAILABLE"})
    report = {
        "result": "NOTERI_GIT_STATE_READONLY",
        "correlation_id": args.correlation_id,
        "expected_head": EXPECTED_HEAD,
        "targets": result,
        "state_changed": False,
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
