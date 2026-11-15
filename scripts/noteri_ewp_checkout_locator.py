#!/usr/bin/env python3
"""Localizador somente leitura do checkout governado do Worker Pool no Noteri."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
from pathlib import Path

CONFIRM = "LOCATE-EWP-EXISTING-CHECKOUT-READONLY"
REPO = "ericson-j-santos/engineering-worker-pool"
ROOT = Path(r"C:\dev\chatgpt-workers")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_CHILDREN = 10000
MAX_MATCHING_NAMES = 120


def git_text(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=7, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode or len(result.stdout) > 4096:
        return None
    return result.stdout.strip()


def candidate(root: Path) -> dict[str, object] | None:
    if root.is_symlink() or not root.is_dir() or not (root / ".git").exists():
        return None
    actual = git_text(root, "rev-parse", "--show-toplevel")
    sha = git_text(root, "rev-parse", "HEAD")
    remote = git_text(root, "config", "--get", "remote.origin.url")
    if not actual or not sha or not SHA.fullmatch(sha) or not remote:
        return None
    try:
        if Path(actual).resolve() != root.resolve():
            return None
    except (OSError, ValueError):
        return None
    # Compara identidade, nunca registra URL, token ou credencial.
    normalized = remote.lower().replace("\\", "/").rstrip("/")
    if not (normalized.endswith("/" + REPO)
            or normalized.endswith("/" + REPO + ".git")
            or normalized.endswith(":" + REPO + ".git")):
        return None
    return {"root": str(root), "head": sha, "tracked_clean": (
        git_text(root, "status", "--porcelain", "--untracked-files=no") == ""
    )}


def locate(host: str, platform: str, confirm: str, expected_sha: str,
           checkout: Path) -> dict[str, object]:
    if confirm != CONFIRM or host.casefold() != "noteri" or platform != "nt":
        return {"result": "EWP_LOCATOR_BLOCKED", "reason": "HOST_OR_CONFIRM"}
    if not SHA.fullmatch(expected_sha) or git_text(checkout, "rev-parse", "HEAD") != expected_sha:
        return {"result": "EWP_LOCATOR_BLOCKED", "reason": "SOURCE_SHA_MISMATCH"}
    found = []
    try:
        inspected = 0
        matching_names = 0
        for path in ROOT.iterdir():
            inspected += 1
            if inspected > MAX_CHILDREN:
                return {"result": "EWP_LOCATOR_BLOCKED", "reason": "LIMIT_EXCEEDED"}
            name = path.name.casefold()
            if not any(fragment in name for fragment in
                       ("engineering-worker-pool", "worker-pool", "ewp")):
                continue
            matching_names += 1
            if matching_names > MAX_MATCHING_NAMES:
                return {"result": "EWP_LOCATOR_BLOCKED", "reason": "MATCH_LIMIT_EXCEEDED"}
            result = candidate(path)
            if result is not None:
                found.append(result)
    except OSError:
        return {"result": "EWP_LOCATOR_BLOCKED", "reason": "ROOT_UNAVAILABLE"}
    return {"result": "EWP_CHECKOUT_READONLY_LOCATED",
            "candidate_count": len(found), "candidates": found,
            "state_changed": False, "claim_performed": False,
            "source_sha": expected_sha}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--expected-sha", required=True)
    a = parser.parse_args()
    receipt = locate(socket.gethostname(), os.name, a.confirm, a.expected_sha,
                     Path(__file__).resolve().parents[1])
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["result"] == "EWP_CHECKOUT_READONLY_LOCATED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
