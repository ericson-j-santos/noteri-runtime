#!/usr/bin/env python3
"""Read-only Rules #219 / Worker Pool #61 source and host admission inventory.

Only the existing, separately authorized Noteri Session Launcher + Command
Gateway may invoke this as Risk1. It cannot install, dispatch, stage, call Qwen
inference, claim a lease, grant cost approval, or certify READY_FOR_PR.

The source-only verifier is reusable by a hosted CI; its synthetic tests are
NEVER a physical host receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

NOTERI_REPO = "ericson-j-santos/noteri-runtime"
RULES_REPO = "ericson-j-santos/chatgpt-operational-rules"
POOL_REPO = "ericson-j-santos/engineering-worker-pool"
RULES_SHA = "40e3db3ef8b1fe367d79b878b8d9d91930d2337b"
POOL_SHA = "87885bb8eab5c694b8d206a709b9a8c213cf5500"
MODEL = "qwen2.5-coder:7b"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
PINNED_RULES_FILES = {
    "scripts/rules219_model_propose.py":
        "55a49ca39beb049f0f5d084eafa0c85f5e906ef4b9b366c32494f9e5fad37719",
    "scripts/rules219_model_apply.py":
        "eac267ea2d531e8e0d62326a6f48b73600c14df6cb4329884b0f609d1328ad05",
    "scripts/rules219_validator.py":
        "861560fe377e9c0e15eb5e5826859357bcce3d7bf2b3343eb93d90a2747943ee",
    "scripts/builder_manifest_stage.py":
        "422924c9bb5a409135328d41c1d5508ccd1e88da7fae02dc8beead5294ea1010",
}
POOL_BINDING_BLOB = "66e2a42a579c26901c63b8524a94dcdf76c17343"
MAX_OUTPUT_BYTES = 65536


class Blocked(RuntimeError):
    """Only fixed, non-sensitive codes are returned to an external runner."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Blocked(reason)


def git(root: Path, *args: str) -> bytes:
    """All Git observations are fixed read-only commands without a shell."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], check=False,
            capture_output=True, timeout=15,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("NOTERI_219_GIT_UNAVAILABLE") from None
    require(result.returncode == 0 and len(result.stdout) <= MAX_OUTPUT_BYTES,
            "NOTERI_219_GIT_READBACK_INVALID")
    return result.stdout


def verify_checkout(root: Path, *, repository: str, sha: str) -> None:
    """No checkout, fetch, pull, status mutation or branch change."""
    require(root.is_dir() and not root.is_symlink()
            and root == root.resolve(), "NOTERI_219_SOURCE_PATH_INVALID")
    observed = git(root, "rev-parse", "--show-toplevel").decode("utf-8", "strict").strip()
    require(Path(observed).resolve() == root,
            "NOTERI_219_SOURCE_ROOT_MISMATCH")
    require(git(root, "rev-parse", "HEAD").decode().strip() == sha
            and git(root, "rev-parse", "--abbrev-ref", "HEAD").strip()
            == b"HEAD",
            "NOTERI_219_SOURCE_SHA_DRIFT")
    # The expected detached checkout still needs an authenticated origin.
    remote = git(root, "remote", "get-url", "origin").decode().strip()
    require(remote in {
        f"https://github.com/{repository}",
        f"https://github.com/{repository}.git",
    }, "NOTERI_219_SOURCE_ORIGIN_DRIFT")
    require(git(root, "remote").splitlines() == [b"origin"],
            "NOTERI_219_SOURCE_EXTRA_REMOTE")
    # Do not misinterpret sibling repositories under the runner's checkout as
    # source changes; separately validate their tracked bytes below.
    require(not git(root, "status", "--porcelain", "--untracked-files=no"),
            "NOTERI_219_SOURCE_TRACKED_DIRTY")
    if repository != NOTERI_REPO:
        require(not git(root, "status", "--porcelain", "--untracked-files=all"),
                "NOTERI_219_SOURCE_UNTRACKED")


def verify_file(root: Path, relative: str, *, digest: str) -> None:
    file = root / relative
    require(file.is_file() and not file.is_symlink()
            and file.resolve().is_relative_to(root)
            and file.stat().st_size <= 256000,
            "NOTERI_219_SOURCE_FILE_INVALID")
    body = file.read_bytes()
    require(hashlib.sha256(body).hexdigest() == digest,
            "NOTERI_219_SOURCE_FILE_DIGEST_DRIFT")
    # Prevent a working tree file from disagreeing with its pinned Git object.
    require(git(root, "show", "HEAD:" + relative) == body,
            "NOTERI_219_SOURCE_INDEX_DRIFT")


def verify_pins(*, host: Path, rules: Path, pool: Path,
                host_sha: str) -> dict[str, Any]:
    """Verify exact original repositories, Git commit SHAs, and script bytes."""
    require(SHA40.fullmatch(host_sha) is not None,
            "NOTERI_219_HOST_SHA_INVALID")
    require(len({host, rules, pool}) == 3,
            "NOTERI_219_NONISOLATED_CHECKOUT")
    for root, repo, sha in (
        (host, NOTERI_REPO, host_sha),
        (rules, RULES_REPO, RULES_SHA),
        (pool, POOL_REPO, POOL_SHA),
    ):
        verify_checkout(root, repository=repo, sha=sha)
    # A hosted CI may have two independent checkout directories nested under
    # its source workspace. Only these exact untracked roots are tolerable.
    permitted = {
        "?? " + str(other.relative_to(host)).replace("\\", "/") + "/"
        for other in (rules, pool) if other.is_relative_to(host)
    }
    observed = set(git(host, "status", "--porcelain",
                       "--untracked-files=normal").decode().splitlines())
    require(observed == permitted, "NOTERI_219_HOST_UNTRACKED_SCOPE_DRIFT")
    for path, digest in PINNED_RULES_FILES.items():
        verify_file(rules, path, digest=digest)
    binding_sha = git(pool, "rev-parse",
                      "HEAD:app/rules219_manifest_command.py").decode().strip()
    require(binding_sha == POOL_BINDING_BLOB,
            "NOTERI_219_POOL_BINDING_BLOB_DRIFT")
    adapter = (pool / "app/rules219_manifest_command.py").read_bytes()
    require(git(pool, "show", "HEAD:app/rules219_manifest_command.py") == adapter
            and RULES_SHA.encode() in adapter
            and all(d.encode() in adapter for d in PINNED_RULES_FILES.values()),
            "NOTERI_219_POOL_BINDING_SOURCE_DRIFT")
    return {
        "rules_sha": RULES_SHA, "worker_sha": POOL_SHA,
        "host_sha": host_sha, "script_count": len(PINNED_RULES_FILES),
        "source_pins_verified": True,
    }


def inspect_model_tags(payload: Any) -> str:
    """An Ollama inventory observation, NOT inference/model install proof."""
    require(type(payload) is dict and type(payload.get("models")) is list
            and len(payload["models"]) <= 64,
            "NOTERI_219_MODEL_INVENTORY_INVALID")
    exact = [
        item for item in payload["models"]
        if type(item) is dict and item.get("name") == MODEL
    ]
    require(len(exact) == 1, "NOTERI_219_MODEL_TAG_MISSING_OR_DUPLICATE")
    value = exact[0]
    digest = value.get("digest")
    require(type(digest) is str and SHA64.fullmatch(digest) is not None
            and not value.get("remote_host") and not value.get("remote_model"),
            "NOTERI_219_MODEL_NOT_LOCAL_OR_DIGEST_INVALID")
    return digest


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def local_model_inventory() -> dict[str, Any]:
    """Single local GET, no proxy, redirects, POST, download or model startup."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
    )
    try:
        with opener.open("http://127.0.0.1:11434/api/tags", timeout=12) as res:
            require(res.status == 200
                    and res.geturl() == "http://127.0.0.1:11434/api/tags",
                    "NOTERI_219_MODEL_RESPONSE_UNTRUSTED")
            data = res.read(65537)
    except (OSError, urllib.error.URLError, ValueError):
        raise Blocked("NOTERI_219_MODEL_LOOPBACK_UNAVAILABLE") from None
    require(len(data) <= 65536, "NOTERI_219_MODEL_RESPONSE_TOO_LARGE")
    try:
        result = json.loads(data)
    except (ValueError, UnicodeError):
        raise Blocked("NOTERI_219_MODEL_RESPONSE_INVALID") from None
    require(type(result) is dict, "NOTERI_219_MODEL_RESPONSE_INVALID")
    return result


def context_observed(env: dict[str, str], *, host_name: str,
                     platform: str, expected_host_sha: str) -> None:
    """Schema check only. The external Launcher/Gateway owns attestation."""
    require(env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_REPOSITORY") == NOTERI_REPO
            and env.get("RUNNER_NAME") == "Noteri-runtime"
            and platform == "nt" and host_name.casefold() == "noteri",
            "NOTERI_219_HOST_CONTEXT_INVALID")
    require(env.get("GITHUB_SHA") == expected_host_sha
            and env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
            and env.get("SESSION_STATE_VALIDATED") == "true"
            and env.get("SESSION_GATEWAY_BOUND") == "true"
            and SHA64.fullmatch(env.get("SESSION_SNAPSHOT_SHA256", ""))
            is not None,
            "NOTERI_219_SESSION_CONTEXT_UNATTESTED")
    # This function does NOT accept or certify a task, lease, paid quota,
    # installed app, CAS, cost approval, or authorization.


def inspect_readonly(*, env: dict[str, str], host: Path,
                     rules: Path, pool: Path,
                     tags: dict[str, Any], host_name: str,
                     platform: str) -> dict[str, Any]:
    """Never returns 'ready'; read-only data is insufficient to authorize Risk2."""
    host_sha = env.get("GITHUB_SHA", "")
    context_observed(env, host_name=host_name, platform=platform,
                     expected_host_sha=host_sha)
    pins = verify_pins(host=host, rules=rules, pool=pool, host_sha=host_sha)
    digest = inspect_model_tags(tags)
    return {
        "result": "NOTERI_219_READONLY_OBSERVATIONS",
        **pins,
        "model": MODEL,
        "observed_model_digest": digest,
        "session_schema_checked": True,
        "gateway_execution_attested": False,
        "cost_zero_attested": False,
        "lease_attested": False,
        "artifact_cas_attested": False,
        "builder_executed": False,
        "activation_authorized": False,
        "ready_for_builder": False,
        "secrets_read": False,
        "state_changed": False,
    }


def main() -> int:
    """For a reviewed Risk1 Gateway call only; no user-defined commands."""
    if len(sys.argv) != 1:
        raise SystemExit("NOTERI_219_ARGUMENTS_FORBIDDEN")
    try:
        require(os.environ.get("SESSION_TARGET_PATH"),
                "NOTERI_219_SESSION_TARGET_REQUIRED")
        root = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        host = Path(os.environ["SESSION_TARGET_PATH"]).resolve(strict=True)
        context_observed(
            dict(os.environ), host_name=socket.gethostname(),
            platform=os.name, expected_host_sha=os.environ.get("GITHUB_SHA", ""),
        )
        result = inspect_readonly(
            env=dict(os.environ), host=host,
            rules=(root / "_rules").resolve(strict=True),
            pool=(root / "_worker_pool").resolve(strict=True),
            tags=local_model_inventory(),
            host_name=socket.gethostname(), platform=os.name,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, UnicodeError, KeyError) as exc:
        reason = str(exc) if type(exc) is Blocked else "NOTERI_219_PREFLIGHT_UNAVAILABLE"
        print(json.dumps({
            "result": "NOTERI_219_READONLY_BLOCKED", "reason_code": reason,
            "ready_for_builder": False, "state_changed": False,
            "secrets_read": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
