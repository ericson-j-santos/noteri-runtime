#!/usr/bin/env python3
"""Typed candidate-only synchronization of Noteri Worker Pool rules SHA.

Reads the authoritative GitHub rules branch; can prepare one exact code edit
inside a clean, non-protected Git worktree. Never installs, restarts, stops,
registers a service, creates a PR, merges, or writes an active runner.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

RULES_URL = (
    "https://api.github.com/repos/"
    "ericson-j-santos/chatgpt-operational-rules/branches/main"
)
RUNNER_REL = Path("scripts/noteri_worker_pool_api_runner.py")
REPO_NAME = "ericson-j-santos/noteri-runtime"
SHA = re.compile(r"[0-9a-f]{40}\Z")
PIN_LINE = re.compile(r'^(RULES_SHA\s*=\s*)"[0-9a-f]{40}"(\s*)$')
ALLOWED_BRANCH = re.compile(r"(feat|fix|repair)/[A-Za-z0-9][A-Za-z0-9._/-]{2,150}\Z")
CONFIRM = "PREPARE-RULES-PIN-CANDIDATE"


class SyncBlocked(RuntimeError):
    """A bounded failure reason without local paths, tokens or response bodies."""


def verified_sha(value: Any) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise SyncBlocked("BLOCKED_RULES_SHA")
    return value


def canonical_rules_sha(*, opener=None) -> str:
    """Fixed public GitHub URL; no redirects, credentials or arbitrary source."""
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler())
    request = urllib.request.Request(
        RULES_URL,
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": "NoteriWorkerPoolRulesAudit/1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=8) as response:
            if (response.geturl() != RULES_URL or response.status != 200 or
                    response.headers.get_content_type() != "application/json"):
                raise SyncBlocked("BLOCKED_CANONICAL_ORIGIN")
            data = response.read(16385)
            if len(data) > 16384:
                raise SyncBlocked("BLOCKED_CANONICAL_RESPONSE_SIZE")
        payload = json.loads(data.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("name") != "main":
            raise SyncBlocked("BLOCKED_CANONICAL_RESPONSE")
        return verified_sha(payload["commit"]["sha"])
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError):
        raise SyncBlocked("BLOCKED_CANONICAL_UNAVAILABLE") from None


def pinned_sha(source: str) -> str:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        raise SyncBlocked("BLOCKED_RUNNER_SOURCE") from None
    bindings = [
        statement for statement in tree.body
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "RULES_SHA"
            for target in statement.targets
        )
    ]
    # Reject any secondary or nested reassignment; a syntactically valid
    # literal pin must not be silently overwritten at runtime.
    writes = [
        node for node in ast.walk(tree)
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "RULES_SHA"
                    for t in node.targets)
        ) or (
            isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
            and isinstance(node.target, ast.Name)
            and node.target.id == "RULES_SHA"
        )
    ]
    if (len(bindings) != 1 or len(bindings[0].targets) != 1
            or writes != bindings):
        raise SyncBlocked("BLOCKED_RUNNER_PIN")
    statement = bindings[0]
    if (not isinstance(statement.targets[0], ast.Name)
            or statement.targets[0].id != "RULES_SHA"
            or not isinstance(statement.value, ast.Constant)):
        raise SyncBlocked("BLOCKED_RUNNER_PIN")
    return verified_sha(statement.value.value)


def candidate_source(original: str, canonical: str) -> str:
    canonical = verified_sha(canonical)
    current = pinned_sha(original)
    lines = original.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if PIN_LINE.fullmatch(line.rstrip("\r\n"))]
    if len(hits) != 1 or current not in lines[hits[0]]:
        raise SyncBlocked("BLOCKED_RUNNER_PIN")
    if current == canonical:
        return original
    index = hits[0]
    raw = lines[index]
    newline = "\r\n" if raw.endswith("\r\n") else ("\n" if raw.endswith("\n") else "")
    match = PIN_LINE.fullmatch(raw.rstrip("\r\n"))
    if match is None:
        raise SyncBlocked("BLOCKED_RUNNER_PIN")
    lines[index] = f'{match.group(1)}"{canonical}"{match.group(2)}{newline}'
    updated = "".join(lines)
    if pinned_sha(updated) != canonical or len(updated) != len(original):
        raise SyncBlocked("BLOCKED_CANDIDATE_VERIFICATION")
    return updated


def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True,
            timeout=12, check=False,
            env={"PATH": os.environ.get("PATH", os.defpath),
                 "GIT_TERMINAL_PROMPT": "0",
                 "GIT_CONFIG_GLOBAL": os.devnull,
                 "GIT_CONFIG_SYSTEM": os.devnull},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SyncBlocked("BLOCKED_GIT_UNAVAILABLE") from None
    if proc.returncode != 0 or len(proc.stdout) > 4096:
        raise SyncBlocked("BLOCKED_GIT_STATE")
    return proc.stdout.strip()


def candidate_preflight(repo: Path, expected_head: str) -> dict[str, str]:
    verified_sha(expected_head)
    if not repo.is_dir() or repo.is_symlink():
        raise SyncBlocked("BLOCKED_WORKTREE")
    if Path(_git(repo, "rev-parse", "--show-toplevel")).resolve() != repo.resolve():
        raise SyncBlocked("BLOCKED_WORKTREE")
    head = _git(repo, "rev-parse", "HEAD")
    branch = _git(repo, "symbolic-ref", "--short", "HEAD")
    remote = _git(repo, "remote", "get-url", "origin")
    if (head != expected_head or not ALLOWED_BRANCH.fullmatch(branch)
            or remote.removesuffix(".git") not in {
                "https://github.com/" + REPO_NAME,
                "git@github.com:" + REPO_NAME,
            }):
        raise SyncBlocked("BLOCKED_WORKTREE_IDENTITY")
    if _git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise SyncBlocked("BLOCKED_WORKTREE_DIRTY")
    return {"head": head, "branch": branch}


def sync(*, repo: Path, canonical: str, mode: str,
         expected_head: str = "", confirm: str = "") -> dict[str, Any]:
    canonical = verified_sha(canonical)
    if mode not in {"plan", "check", "prepare"}:
        raise SyncBlocked("BLOCKED_MODE")
    runner = repo / RUNNER_REL
    if (runner.is_symlink() or runner.parent.is_symlink() or
            not runner.is_file() or runner.stat().st_nlink != 1):
        raise SyncBlocked("BLOCKED_RUNNER_PATH")
    try:
        original_bytes = runner.read_bytes()
        original = original_bytes.decode("utf-8")
    except (OSError, UnicodeError):
        raise SyncBlocked("BLOCKED_RUNNER_READ") from None
    updated = candidate_source(original, canonical)
    current = pinned_sha(original)
    plan = {
        "schema_version": "1", "result": "RULES_SHA_ALIGNED"
        if updated == original else "RULES_SHA_DRIFT",
        "canonical_sha": canonical, "pinned_sha": current,
        "candidate_path": RUNNER_REL.as_posix(),
        "change_required": updated != original,
        "source_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "candidate_sha256": hashlib.sha256(updated.encode("utf-8")).hexdigest(),
        "service_changed": False, "installed_runner_changed": False,
        "branch_merged": False, "deployed": False, "cost_additional_brl": 0,
    }
    if mode in {"plan", "check"}:
        return plan
    if confirm != CONFIRM:
        raise SyncBlocked("BLOCKED_CONFIRM")
    candidate_preflight(repo, expected_head)
    if updated == original:
        return {**plan, "result": "CANDIDATE_ALREADY_ALIGNED",
                "candidate_written": False}
    # The only permitted write is the tracked *source* in a clean feature/
    # fix/repair worktree. This function has no service or Task Scheduler API.
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=runner.parent, prefix=".rules-pin-", delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(updated.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, runner)
        temp_path = None
        if runner.read_bytes() != updated.encode("utf-8"):
            raise SyncBlocked("BLOCKED_POSTWRITE_READBACK")
        return {**plan, "result": "CANDIDATE_PREPARED",
                "candidate_written": True}
    except (OSError, ValueError):
        raise SyncBlocked("BLOCKED_CANDIDATE_WRITE") from None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Worker Pool fixed-source rules SHA sync")
    parser.add_argument("--mode", choices=("plan", "check", "prepare"), default="plan")
    parser.add_argument("--expected-head", default="")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    # This script runs only from the versioned source repository; no caller
    # may supply an arbitrary root, remote, target file, or rules SHA.
    repo = Path(__file__).resolve().parents[1]
    try:
        canonical = canonical_rules_sha()
        result = sync(repo=repo, canonical=canonical, mode=args.mode,
                      expected_head=args.expected_head, confirm=args.confirm)
        ok = (args.mode != "check" or not result["change_required"]) and result["result"] in {
            "RULES_SHA_ALIGNED", "RULES_SHA_DRIFT",
            "CANDIDATE_ALREADY_ALIGNED", "CANDIDATE_PREPARED",
        }
    except SyncBlocked as exc:
        result, ok = {
            "result": str(exc), "service_changed": False,
            "installed_runner_changed": False, "deployed": False,
        }, False
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
