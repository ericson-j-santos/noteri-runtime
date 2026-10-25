#!/usr/bin/env python3
"""Read-only readiness check for the pinned native Noteri Worker Pool release.

No package installation, service creation, credential bytes or HTTP mutations.
The result deliberately does not authorize activation.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_stage as stage

SOURCE_SHA = reference.SOURCE_SHA
RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
TASK_NAME = r"\Automation\NoteriWorkerPoolApi"
PORT = 8097
MIN_FREE_BYTES = 512 * 1024 * 1024
PIN = re.compile(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.-]+)\Z")


def required_packages(requirements: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = PIN.fullmatch(stripped)
        if match is None:
            raise ValueError("requirements_not_exactly_pinned")
        name, version = match.groups()
        key = name.lower().replace("_", "-")
        if key in result:
            raise ValueError("requirements_duplicate")
        result[key] = version
    if not result:
        raise ValueError("requirements_empty")
    return result


def package_status(requirements: Path) -> dict:
    required = required_packages(requirements)
    mismatched = []
    missing = []
    for name, expected in required.items():
        try:
            observed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(name)
        else:
            if observed != expected:
                mismatched.append(name)
    return {"required_count": len(required), "missing": sorted(missing),
            "version_mismatch": sorted(mismatched),
            "ready": not missing and not mismatched}


def task_status() -> str:
    try:
        result = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", TASK_NAME, "/FO", "CSV"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return "present_unverified" if result.returncode == 0 else "absent_or_unreadable"


def listener_status() -> str:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=1):
            return "listening_unverified"
    except ConnectionRefusedError:
        return "not_listening"
    except OSError:
        return "unknown"


def assess(*, localappdata: Path, hostname: str, platform: str,
           profile: str | None, python_version: tuple[int, int] | None = None,
           packages=None, listener=None, task=None, free_bytes=None) -> dict:
    base = {"schema_version": "1", "source_sha": SOURCE_SHA,
            "rules_sha": RULES_SHA, "host": "Noteri", "state_changed": False,
            "activated": False, "token_bytes_read": False,
            "service_identity_verified": False, "activation_authorized": False}
    if platform != "nt" or hostname.casefold() != "noteri" or profile != "NORMAL":
        return {**base, "result": "BLOCKED_HOST_PROFILE"}
    release = localappdata / reference.RELEASES_RELATIVE / SOURCE_SHA
    try:
        stage.ensure_no_link_components(release)
        manifest_path = release / "manifest.json"
        if not manifest_path.is_file() or stage.is_link(manifest_path):
            return {**base, "result": "BLOCKED_RELEASE"}
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict)
                or manifest.get("source_sha") != SOURCE_SHA
                or manifest.get("source_repo") != stage.EXPECTED_REPO
                or manifest.get("kind") != "noteri_worker_pool_stage_only"
                or manifest.get("activated") is not False
                or not stage.validate_staged(release, manifest)):
            return {**base, "result": "BLOCKED_RELEASE"}
        credential = reference.qualify(localappdata=localappdata, hostname=hostname,
                                       profile=profile, platform=platform)
        if credential["result"] != "REFERENCE_PRIVATE_UNREAD":
            return {**base, "result": "BLOCKED_CREDENTIAL_REFERENCE"}
        versions = python_version or sys.version_info[:2]
        if versions < (3, 11):
            return {**base, "result": "BLOCKED_PYTHON_VERSION"}
        package_check = packages if packages is not None else package_status(release / "requirements.txt")
        available = free_bytes if free_bytes is not None else shutil.disk_usage(release).free
        if available < MIN_FREE_BYTES:
            return {**base, "result": "BLOCKED_DISK_SPACE"}
        if not package_check["ready"]:
            return {**base, "result": "BLOCKED_DEPENDENCIES", "packages": package_check,
                    "credential_reference_private": True, "release_verified": True}
        port_check = listener if listener is not None else listener_status()
        task_check = task if task is not None else task_status()
        if port_check != "not_listening":
            return {**base, "result": "BLOCKED_PORT_OR_UNKNOWN_LISTENER",
                    "listener": port_check}
        if task_check != "absent_verified":
            return {**base, "result": "BLOCKED_TASK_INVENTORY",
                    "task": task_check}
        return {**base, "result": "READY_FOR_ACTIVATION_DESIGN",
                "python_version": ".".join(map(str, versions)),
                "packages": package_check, "listener": port_check, "task": task_check,
                "free_space_sufficient": True, "credential_reference_private": True,
                "release_verified": True}
    except (OSError, ValueError, TypeError, KeyError, stage.StageBlocked):
        return {**base, "result": "BLOCKED_INTEGRITY"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    local = os.environ.get("LOCALAPPDATA", "")
    profile = None
    if local:
        try:
            profile_path = Path(local) / reference.PROFILE_RELATIVE
            profile = json.loads(profile_path.read_text(encoding="utf-8")).get("profile")
        except (OSError, ValueError, AttributeError):
            pass
    result = assess(localappdata=Path(local), hostname=socket.gethostname(),
                    platform=os.name, profile=profile)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "READY_FOR_ACTIVATION_DESIGN" else 2


if __name__ == "__main__":
    raise SystemExit(main())
