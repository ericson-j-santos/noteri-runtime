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
import unicodedata

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


def _surrogate_replaced(value: str) -> str:
    return "".join("\ufffd" if unicodedata.category(ch) == "Cs" else ch
                   for ch in value)


def _empty_directory_readonly(path: Path) -> bool | None:
    try:
        if not path.is_dir() or path.is_symlink():
            return None
        return not any(path.iterdir())
    except OSError:
        return None


def raw_directory_identity(root: Path) -> dict:
    """Crosscheck a Git stderr byte-name against actual directory entries.

    The output deliberately has no paths, entry names or raw stderr bytes.
    Read-only; no global Git settings or filesystem mutations.
    """
    command = ("git", "ls-files", "--others", "--exclude-standard",
               "-z", "--", ".")
    try:
        check = subprocess.run(
            command, cwd=root, capture_output=True, text=False,
            shell=False, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "GIT_PROBE_UNAVAILABLE"}
    stderr = check.stderr or b""
    pattern = re.search(
        rb"could not open directory ['\"]([^'\"]{1,128})['\"]:",
        stderr, re.IGNORECASE,
    )
    if pattern is None:
        return {
            "status": "NO_DIRECTORY_WARNING" if check.returncode == 0 and not stderr
                      else "UNKNOWN_WARNING",
            "stderr_raw_sha256": hashlib.sha256(stderr).hexdigest(),
        }
    raw = pattern.group(1)
    try:
        entries = tuple(item.name for item in os.scandir(root))
    except OSError:
        return {"status": "PARENT_UNREADABLE"}
    matches = []
    nonascii_entries = [name for name in entries if not name.isascii()]
    for encoding in ("utf-8", "cp1252", "cp850", "cp437"):
        try:
            decoded = raw.decode(encoding, errors="strict")
        except UnicodeError:
            continue
        value = decoded.rstrip("/").rstrip("\\")
        if (not value or "/" in value or "\\" in value or ":" in value
                or value in {".", ".."} or "\x00" in value):
            continue
        exact = value in entries
        folded = sum(n.casefold() == value.casefold() for n in entries)
        candidate = root / value
        matches.append({
            "encoding": encoding,
            "exact_entry": exact,
            "casefold_entry_count": folded,
            "exists": candidate.exists(),
            "is_dir": candidate.is_dir(),
            "is_symlink": candidate.is_symlink(),
            "normalized_nfc_match": any(
                unicodedata.normalize("NFC", n) == unicodedata.normalize("NFC", value)
                for n in nonascii_entries
            ),
            "normalized_nfkc_match": any(
                unicodedata.normalize("NFKC", n) == unicodedata.normalize("NFKC", value)
                for n in nonascii_entries
            ),
            "char_categories": [
                unicodedata.category(char) for char in value[:12]
            ],
            "replacement_character_count": value.count("\ufffd"),
            "surrogate_replacement_match_count": sum(
                _surrogate_replaced(n) == value
                for n in nonascii_entries
            ),
            "matching_surrogate_directory_empty": [
                _empty_directory_readonly(root / n) for n in nonascii_entries
                if _surrogate_replaced(n) == value
                and (root / n).is_dir() and not (root / n).is_symlink()
            ][:3],
        })
    return {
        "status": "DIRECTORY_WARNING_CROSSCHECKED",
        "raw_name_byte_count": len(raw),
        "raw_name_ascii": raw.isascii(),
        "root_entry_count": len(entries),
        "nonascii_root_entry_count": len(nonascii_entries),
        "nonascii_entry_kinds": [
            {"chars": len(name), "is_dir": (root / name).is_dir(),
             "symlink": (root / name).is_symlink(),
             "categories": [unicodedata.category(ch) for ch in name[:12]]}
            for name in nonascii_entries[:5]
        ],
        "candidate_decodings": matches,
        "raw_name_sha256": hashlib.sha256(raw).hexdigest(),
        "stderr_raw_sha256": hashlib.sha256(stderr).hexdigest(),
        "exit_code": check.returncode,
    }


def directory_warning_details(stderr: str, root: Path) -> dict:
    """Narrow directory classification; refuse to print arbitrary filenames."""
    pattern = re.search(
        r"could not open directory ['\"]([^'\"]{1,128})['\"]:\s*([^\r\n]{1,100})",
        stderr, re.IGNORECASE,
    )
    if not pattern:
        return {"directory_class": "UNKNOWN", "reason": "UNKNOWN"}
    value, cause = pattern.groups()
    parts = Path(value.replace("\\", "/"))
    if parts.is_absolute() or ".." in parts.parts or ":" in value:
        return {"directory_class": "REDACTED", "reason": "UNKNOWN"}
    name = parts.as_posix().rstrip("/").casefold()
    allowed = frozenset(("tmp", "temp", "__pycache__", ".pytest_cache",
                         ".mypy_cache", "venv", ".venv", "logs", "reports",
                         "build", "dist", "artifacts"))
    result = {
        "directory_class": name if name in allowed else "OTHER_RELATIVE",
        "directory_hash16": hashlib.sha256(value.encode()).hexdigest()[:16],
        "reason": ("NOT_FOUND" if "no such file or directory" in cause.casefold()
                   else "ACCESS_DENIED" if "permission denied" in cause.casefold()
                   else "OTHER"),
    }
    target = root / parts
    # Safe shape and parent metadata: no private path or entry name emitted.
    result["path_segments"] = len(parts.parts)
    result["target_length"] = len(value)
    result["target_ascii"] = value.isascii()
    result["name_length"] = len(parts.name)
    result["windows_reserved_name"] = parts.name.split(".")[0].casefold() in {
        "con", "prn", "aux", "nul", *("com" + str(n) for n in range(1, 10)),
        *("lpt" + str(n) for n in range(1, 10)),
    }
    try:
        result["parent_present"] = target.parent.is_dir()
        result["directory_present"] = target.exists()
        result["directory_symlink"] = target.is_symlink()
        result["parent_is_symlink"] = target.parent.is_symlink()
        with os.scandir(target.parent) as entries:
            result["parent_has_exact_entry"] = any(
                item.name == target.name for item in entries
            )
    except OSError:
        result["parent_present"] = None
        result["parent_has_exact_entry"] = None
    return result


def compare_readonly_git_options(root: Path) -> list[dict]:
    """Check whether Git's untracked-cache/fsmonitor options cause the warning.

    Test only bounded Git read queries. Do not change repository configuration.
    """
    profiles = (
        ("without_untracked_cache", ("-c", "core.untrackedCache=false")),
        ("without_fsmonitor", ("-c", "core.fsmonitor=false")),
        ("both_disabled_for_query", ("-c", "core.untrackedCache=false",
                                     "-c", "core.fsmonitor=false")),
    )
    results = []
    for name, settings in profiles:
        command = ("git", *settings, "ls-files", "--others", "--exclude-standard",
                   "-z", "--", ".")
        try:
            done = subprocess.run(
                command, cwd=root, capture_output=True, text=True,
                encoding="utf-8", errors="replace", shell=False,
                timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            results.append({"profile": name, "status": "EXECUTION_ERROR"})
            continue
        results.append({
            "profile": name,
            "exit_code": done.returncode,
            "stderr_type": classify_stderr(done.stderr or ""),
            "stderr_code": error_details(done.stderr or "")["message_code"],
            "stderr_sha256": hashlib.sha256(done.stderr.encode()).hexdigest()
                             if done.stderr else None,
        })
    return results


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



def _stable_json_record(path: Path) -> dict | None:
    """Read an existing control-plane record twice; never disclose its fields."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        return None
    try:
        before = path.read_bytes()
        after = path.read_bytes()
        if before != after or len(before) > 65536:
            return None
        obj = json.loads(before.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except (OSError, UnicodeError, ValueError):
        return None


def _snapshot_digest(payload: dict) -> str:
    body = {key: value for key, value in payload.items()
            if key != "snapshot_sha256"}
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def reservation_attestation(root: Path, state_dir: Path,
                            expected_head: str = EXPECTED_HEAD) -> dict:
    """Read-only admission evidence for the two exact, previously reserved sessions.

    A valid reservation and snapshot do NOT grant a new session control of the
    old worktree. No code here acquires, releases or forges an exclusive lease.
    """
    if root.name not in TARGETS or not SHA.fullmatch(expected_head):
        return {"state": "TARGET_DENIED", "exclusive_lease_proven": False}
    sid = root.name.removeprefix("wt-chat-")
    if not sid or root.is_symlink():
        return {"state": "TARGET_DENIED", "exclusive_lease_proven": False}
    if state_dir.is_symlink() or any(
        (state_dir / part).is_symlink() for part in ("sessions", "snapshots", "locks")
    ):
        return {"state": "STATE_LINK_DENIED", "exclusive_lease_proven": False}
    reservation = _stable_json_record(state_dir / "sessions" / (sid + ".json"))
    snapshot = _stable_json_record(state_dir / "snapshots" / (sid + ".json"))
    if reservation is None or snapshot is None:
        return {"state": "RECORD_MISSING_OR_UNSTABLE",
                "exclusive_lease_proven": False}
    expected_path = os.path.normcase(os.path.abspath(str(root)))
    reserved_path = os.path.normcase(
        os.path.abspath(str(reservation.get("reserved_worktree", ""))))
    snap_path = os.path.normcase(
        os.path.abspath(str(snapshot.get("reserved_worktree", ""))))
    conditions = {
        "reservation_session_matches": reservation.get("session_id") == sid,
        "reservation_materialized": reservation.get("status") == "materialized",
        "reservation_host_matches": str(reservation.get("host", "")).casefold() == "noteri",
        "reservation_sha_matches": reservation.get("base_head") == expected_head,
        "reservation_worktree_matches": expected_path == reserved_path,
        "snapshot_session_matches": snapshot.get("session_id") == sid,
        "snapshot_result_valid": snapshot.get("result") == "BOOTSTRAP_OK",
        "snapshot_sha_integrity": snapshot.get("snapshot_sha256") == _snapshot_digest(snapshot),
        "snapshot_worktree_matches": expected_path == snap_path,
        "snapshot_status_matches": snapshot.get("reservation_status")
                                    == reservation.get("status"),
    }
    return {
        "state": "RESERVATION_ATTESTED_READONLY" if all(conditions.values())
                 else "RESERVATION_MISMATCH",
        "checks": conditions,
        # A read-only record is not an exclusive lease. Never claim ownership.
        "exclusive_lease_proven": False,
        "apply_authorized": False,
    }


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
        if name == "untracked" and stderr:
            detail.update(directory_warning_details(stderr, root))
        steps.append(detail)
        if done.returncode != 0 or stderr.strip() or detail.get("identity"):
            break
    return {
        "status": "GIT_STATE_COMMANDS_CLEAN" if len(steps) == len(COMMANDS)
                  and all(step.get("returncode") == 0
                          and step.get("stderr_type") == "none"
                          and not step.get("identity") for step in steps)
                  else "GIT_STATE_COMMAND_BLOCKED",
        "steps": steps,
        "untracked_areas": isolate_untracked_warning(root) if steps[-1]["step"] == "untracked" and (steps[-1].get("stderr_type") != "none" or steps[-1].get("returncode") != 0) else [],
        "git_option_checks": compare_readonly_git_options(root) if steps[-1]["step"] == "untracked" and (steps[-1].get("stderr_type") != "none" or steps[-1].get("returncode") != 0) else [],
        "raw_directory_identity": raw_directory_identity(root) if steps[-1]["step"] == "untracked" and steps[-1].get("stderr_type") != "none" else {},
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
            local = os.environ.get("LOCALAPPDATA", "")
            control = (reservation_attestation(
                root, Path(local) / "ReqSys" / "CommandGateway",
            ) if local else {"state": "STATE_DIRECTORY_UNAVAILABLE",
                            "exclusive_lease_proven": False})
            result.append({"target": name, "reservation": control, **current})
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
