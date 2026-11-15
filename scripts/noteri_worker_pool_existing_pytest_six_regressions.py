#!/usr/bin/env python3
"""Run exactly six pre-existing pytest regressions with verified installed venv.

Read-only source Git, no downloads/installs, no credentials or privileged tasks.
The six test paths are hardcoded and no arbitrary command or test is accepted.
Live service 8097 is never restarted, reconfigured, claimed or accessed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
from pathlib import Path

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import source_sha
from noteri_python_pytest_inventory_readonly import (
    _validated_candidates, _probe,
)

CONFIRM = "RUN-NOTERI-EXISTING-PYTEST-SIX-REGRESSIONS-DEV"
CORR = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
FILES = (
    "tests/test_noteri_worker_pool_native_plan_workflow.py",
    "tests/test_noteri_worker_pool_native_plan_workflow_windows.py",
    "tests/test_noteri_worker_pool_native_stage.py",
    "tests/test_noteri_worker_pool_native_stage_workflow.py",
    "tests/test_noteri_worker_pool_plan_failure_diagnostic_windows.py",
    "tests/test_noteri_worker_pool_plan_readback.py",
)
# Keep Python -I isolated from ambient PYTHONPATH. The only imported
# working tree is the SHA-validated cwd selected by this program itself.
PYTEST_BRIDGE = (
    "import sys;from pathlib import Path;"
    "root=Path.cwd().resolve();"
    "sys.path.insert(0,str(root));"
    "import pytest;"
    "raise SystemExit(pytest.main(sys.argv[1:]))"
)
EXPECTED_PYTEST_VERSION = "9.0.3"


class Blocked(ValueError):
    pass


def _summary(output: str) -> dict[str, int]:
    # No unbounded output or raw tracebacks leave the authorized workstation.
    tail = output[-10000:]
    return {
        label: int(values[-1]) if (values := re.findall(
            rf"\b(\d+)\s+{re.escape(label)}\b", tail)) else 0
        for label in ("passed", "failed", "error", "errors", "skipped", "deselected")
    }


SAFE_DEPENDENCIES = frozenset((
    "pytest", "yaml", "fastapi", "pydantic", "httpx", "requests",
    "scripts", "app", "noteri_worker_pool_native_stage",
    "noteri_worker_pool_activation_preflight",
))


def _collection_diagnostics(output: str) -> dict:
    """Return only allowlisted module IDs and previously fixed test file names."""
    names = sorted(set(re.findall(
        r"No module named ['\"]([A-Za-z0-9_.-]{1,80})['\"]",
        output[-20000:],
    )))
    missing = [item for item in names if item in SAFE_DEPENDENCIES]
    unrecognized = len([item for item in names if item not in SAFE_DEPENDENCIES])
    collected = set(re.findall(
        r"ERROR collecting (tests[/\\][A-Za-z0-9_.-]+\.py)",
        output[-20000:],
    ))
    fixed = {path.replace("/", "\\"):path for path in FILES}
    fixed.update({path:path for path in FILES})
    error_files = sorted({fixed[name] for name in collected if name in fixed})
    return {
        "missing_known_modules": missing,
        "unrecognized_missing_module_count": unrecognized,
        "known_collection_files": error_files,
        "collection_error_detected": "ERROR collecting" in output,
        "isolated_python": True,
    }


SAFE_FAILURE_TYPES = frozenset((
    "AssertionError", "ValueError", "TypeError", "AttributeError",
    "RuntimeError", "PermissionError", "FileNotFoundError",
    "ModuleNotFoundError", "ImportError", "TimeoutError", "KeyError",
))


def _failed_test_cases(output: str) -> list[dict[str, str]]:
    """Identify failures in the six fixed suites without exposing pytest values.

    Pytest parameter IDs may contain spaces, slashes, colons and other private
    values. Keep only the public test-function name plus a short stable hash.
    """
    allowed = set(FILES)
    result: list[dict[str, str]] = []
    expression = re.compile(
        r"^FAILED (tests[/\\][A-Za-z0-9_.-]+\.py)::([^\r\n]+?)(?:\s+-\s+([^\r\n]*))?$",
        re.MULTILINE,
    )
    for match in expression.finditer(output[-60000:]):
        path = match.group(1).replace("\\", "/")
        if path not in allowed:
            continue
        node = match.group(2)
        base = node.split("[", 1)[0].rsplit("::", 1)[-1]
        if not re.fullmatch(r"test_[A-Za-z0-9_]{1,96}", base):
            continue
        short = base
        if "[" in node or "::" in node:
            short += "-" + hashlib.sha256(node.encode()).hexdigest()[:16]
        detail = match.group(3) or ""
        failure = re.match(r"([A-Za-z]+(?:Error|Exception))\b", detail)
        failure_class = failure.group(1) if failure else None
        result.append({
            "file": path,
            "case": short,
            "failure_class": failure_class if failure_class in SAFE_FAILURE_TYPES
            else "UNCLASSIFIED_FAILURE",
        })
    return result[:60]


def _fixed_test_paths(root: Path) -> tuple[str, ...]:
    base = root.resolve()
    paths: list[str] = []
    for relative in FILES:
        file = root / relative
        if (not file.is_file() or file.is_symlink()
                or not file.resolve().is_relative_to(base)
                or file.stat().st_nlink != 1
                or not 0 < file.stat().st_size <= 256 * 1024):
            raise Blocked("TEST_FILE_MISSING_OR_UNTRUSTED")
        paths.append(relative)
    return tuple(paths)


def run(root: Path, *, local: Path, roaming: Path) -> dict:
    candidates = _validated_candidates(local, roaming)
    python = candidates.get("worker_pool_pinned_venv")
    if python is None:
        raise Blocked("VERIFIED_PYTEST_VENV_NOT_FOUND")
    interpreter = _probe("worker_pool_pinned_venv", python)
    if (interpreter.get("result") != "PYTEST_PRESENT"
            or interpreter.get("pytest_version") != EXPECTED_PYTEST_VERSION
            or interpreter.get("python_version") != "3.11"):
        raise Blocked("VERIFIED_PYTEST_VENV_VERSION_MISMATCH")
    files = _fixed_test_paths(root)
    env = {
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
        "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
        "TEMP": os.environ.get("TEMP", ""),
        "TMP": os.environ.get("TMP", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    # These fixed Windows tests invoke PowerShell 5.1 by its executable name.
    # The intentionally isolated environment has no ambient PATH. Give it
    # only the verified Windows PowerShell directory, never the host PATH.
    if os.name == "nt":
        powershell = (Path(env["SYSTEMROOT"]) / "System32" /
                      "WindowsPowerShell" / "v1.0" / "powershell.exe")
        if not powershell.is_file() or powershell.is_symlink():
            raise Blocked("WINDOWS_POWERSHELL_UNAVAILABLE")
        env["PATH"] = str(powershell.parent)
    command = [
        str(python), "-B", "-I", "-c", PYTEST_BRIDGE,
        "-q", "--disable-warnings", "-p", "no:cacheprovider",
        "-o", "addopts=", "--tb=short", *files,
    ]
    try:
        test = subprocess.run(
            command, cwd=root, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=145, check=False,
        )
        raw = (test.stdout or "") + "\n" + (test.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return {"result": "PYTEST_EXECUTION_UNVERIFIED",
                "test_files": len(files),
                "state_changed": False, "packages_installed": False}
    summary = _summary(raw)
    ok = (test.returncode == 0 and summary["passed"] > 0
          and not any(summary[k] for k in (
              "failed", "error", "errors", "skipped", "deselected")))
    return {
        "result": "PYTEST_SIX_SUITES_PASSED" if ok else "PYTEST_PARTIAL_OR_FAILED",
        "pytest_version": EXPECTED_PYTEST_VERSION,
        "python_version": "3.11", "test_files": len(files),
        "tests": summary, "process_exit_code": test.returncode,
        "collection_diagnostics": _collection_diagnostics(raw),
        "failed_cases": _failed_test_cases(raw),
        "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "state_changed": False, "packages_installed": False,
        "network_accessed": False, "credentials_read": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--confirm", required=True)
    a = p.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        if (not SHA40.fullmatch(a.expected_head)
                or not CORR.fullmatch(a.correlation_id)
                or a.confirm != CONFIRM
                or os.name != "nt"
                or socket.gethostname().casefold() != "noteri"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(root) != a.expected_head):
            raise Blocked("HOST_PROFILE_SOURCE_NOT_ATTESTED")
        local = os.environ.get("LOCALAPPDATA")
        roaming = os.environ.get("APPDATA")
        if not local or not roaming:
            raise Blocked("HOST_APPDATA_UNAVAILABLE")
        result = run(root, local=Path(local), roaming=Path(roaming))
        result.update({"correlation_id":a.correlation_id,
                       "source_sha":a.expected_head})
        print(json.dumps(result,sort_keys=True))
        return 0 if result["result"] == "PYTEST_SIX_SUITES_PASSED" else 2
    except (Blocked, OSError) as exc:
        print(json.dumps({"result":"PYTEST_SIX_SUITES_BLOCKED",
                          "reason":str(exc) if isinstance(exc,Blocked)
                          else "RUNTIME_UNAVAILABLE",
                          "state_changed":False,"packages_installed":False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
