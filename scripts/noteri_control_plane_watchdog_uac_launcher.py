#!/usr/bin/env python3
"""Launcher UAC governado para persistência headless do control plane no Noteri."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog

LAUNCH_CONFIRM = "LAUNCH-NOTERI-CONTROL-PLANE-WATCHDOG-UAC"
SW_SHOWNORMAL = 1


class LauncherError(RuntimeError):
    pass


def validate_launcher(*, host: str, platform: str, confirm: str) -> None:
    if host.casefold() != watchdog.EXPECTED_HOST.casefold():
        raise LauncherError(f"launcher permitido somente no host {watchdog.EXPECTED_HOST}")
    if platform != "nt":
        raise LauncherError("launcher UAC exige Windows")
    if confirm != LAUNCH_CONFIRM:
        raise LauncherError("confirmação UAC inválida")


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def load_metadata(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file():
        raise LauncherError(f"metadata ausente: {resolved}")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if str(payload.get("host") or "").casefold() != watchdog.EXPECTED_HOST.casefold():
        raise LauncherError("metadata pertence a host diferente")
    runner_home = Path(str(payload.get("runner_home") or "")).resolve()
    watchdog.validate_runner_home(runner_home)
    return payload


def _decode_xml(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8", errors="replace")


def task_status() -> dict[str, Any]:
    target = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "schtasks.exe"
    try:
        result = subprocess.run(
            [str(target), "/Query", "/TN", watchdog.TASK_NAME, "/XML"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            return {"exists": False, "error": "task_not_found_or_query_failed"}
        root = ET.fromstring(_decode_xml(result.stdout))
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        enabled_text = (root.findtext("./t:Settings/t:Enabled", default="true", namespaces=ns) or "true").strip()
        logon_type = (root.findtext("./t:Principals/t:Principal/t:LogonType", default="", namespaces=ns) or "").strip()
        boot = root.find("./t:Triggers/t:BootTrigger", ns) is not None
        return {
            "exists": True,
            "enabled": enabled_text.casefold() == "true",
            "trigger_at_startup": boot,
            "logon_type": logon_type,
            "validator": "schtasks_xml",
        }
    except Exception as exc:
        return {"exists": False, "error": type(exc).__name__}


def task_headless_ready(task: dict[str, Any]) -> bool:
    return (
        task.get("exists") is True
        and task.get("enabled") is True
        and task.get("trigger_at_startup") is True
        and str(task.get("logon_type") or "").casefold() == "s4u"
    )


def shell_execute_runas(executable: Path, params: str, cwd: Path) -> int:
    return int(
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(executable),
            params,
            str(cwd),
            SW_SHOWNORMAL,
        )
    )


def powershell_runas(executable: Path, params: str, cwd: Path) -> bool:
    powershell = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        return False
    script = (
        "$ErrorActionPreference='Stop';"
        f"$p=Start-Process -FilePath {json.dumps(str(executable))} "
        f"-ArgumentList {json.dumps(params)} "
        f"-WorkingDirectory {json.dumps(str(cwd))} "
        "-Verb RunAs -PassThru;"
        "if($null -eq $p){exit 2}else{exit 0}"
    )
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    return result.returncode == 0


def shell_application_runas(executable: Path, params: str, cwd: Path) -> bool:
    powershell = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        return False
    script = (
        "$ErrorActionPreference='Stop';"
        "$s=New-Object -ComObject Shell.Application;"
        f"$s.ShellExecute({json.dumps(str(executable))},{json.dumps(params)},{json.dumps(str(cwd))},'runas',1);"
        "Start-Sleep -Milliseconds 500;"
        "exit 0"
    )
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    return result.returncode == 0


def build_install_args(
    *,
    repo_root: Path,
    runner_home: Path,
    source_sha: str,
    result_path: Path,
) -> str:
    argv = [
        str(repo_root / "scripts" / "noteri_control_plane_watchdog.py"),
        "install",
        "--repo-root",
        str(repo_root),
        "--runner-home",
        str(runner_home),
        "--source-sha",
        source_sha,
        "--confirm",
        watchdog.INSTALL_CONFIRM,
        "--result-path",
        str(result_path),
    ]
    return subprocess.list2cmdline(argv)


def _path_is_redirect(path: Path) -> bool:
    """Detect symlinks and Windows junction/reparse points without following them."""
    try:
        details = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(details, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return path.is_symlink() or bool(reparse_flag and attributes & reparse_flag)


def _guard_release_location(runtime_root: Path, release: Path) -> tuple[Path, Path]:
    """Return lexical absolute paths only after proving no redirect in the release tree."""
    root = Path(os.path.abspath(runtime_root))
    candidate = Path(os.path.abspath(release))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise LauncherError("WATCHDOG_INSTALLED_PATH_MISMATCH") from exc

    current = root
    if _path_is_redirect(current):
        raise LauncherError("WATCHDOG_INSTALLED_PATH_REDIRECTED")
    for component in relative.parts:
        current /= component
        if _path_is_redirect(current):
            raise LauncherError("WATCHDOG_INSTALLED_PATH_REDIRECTED")
    return root, candidate


def attest_installed_release(
    metadata: dict[str, Any], expected_sha: str, source: Path,
) -> None:
    """Fail closed on stale or redirected persistent watchdog bytes."""
    if metadata.get("source_sha") != expected_sha:
        raise LauncherError("WATCHDOG_INSTALLED_SHA_MISMATCH")

    runtime_root = watchdog.runtime_root()
    release = runtime_root / "releases" / expected_sha / "scripts" / source.name
    _, release = _guard_release_location(runtime_root, release)

    recorded = metadata.get("release_script")
    if not isinstance(recorded, str) or not recorded.strip():
        raise LauncherError("WATCHDOG_INSTALLED_PATH_MISSING")
    recorded_path = Path(recorded)
    if not recorded_path.is_absolute():
        raise LauncherError("WATCHDOG_INSTALLED_PATH_MISMATCH")
    recorded_absolute = Path(os.path.abspath(recorded_path))
    if os.path.normcase(str(recorded_absolute)) != os.path.normcase(str(release)):
        raise LauncherError("WATCHDOG_INSTALLED_PATH_MISMATCH")
    if _path_is_redirect(source):
        raise LauncherError("WATCHDOG_INSTALLED_SOURCE_REDIRECTED")
    if not source.is_file() or not release.is_file():
        raise LauncherError("WATCHDOG_INSTALLED_RELEASE_MISSING")

    expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    installed_digest = hashlib.sha256(release.read_bytes()).hexdigest()
    if metadata.get("release_sha256") != expected_digest or installed_digest != expected_digest:
        raise LauncherError("WATCHDOG_INSTALLED_DIGEST_MISMATCH")
    if (metadata.get("task") or {}).get("exists") is not True:
        raise LauncherError("WATCHDOG_INSTALLED_TASK_UNVERIFIED")



def finalize(metadata_path: Path, task: dict[str, Any]) -> dict[str, Any]:
    metadata = load_metadata(metadata_path)
    metadata.update(
        {
            "task": task,
            "activation_pending": False,
            "requires_uac_activation": False,
            "headless_persistence": True,
            "runtime_persistent_after_login": True,
            "headless_activated_at": watchdog.now_iso(),
        }
    )
    watchdog.atomic_json(metadata_path, metadata)
    runner_home = Path(str(metadata["runner_home"])).resolve()
    cycle = watchdog.cycle(runner_home)
    return {"metadata": metadata, "cycle": cycle}


def launch(
    *,
    repo_root: Path,
    source_sha: str,
    metadata_path: Path,
    confirm: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    validate_launcher(host=socket.gethostname(), platform=os.name, confirm=confirm)
    source_sha = watchdog.validate_source_sha(source_sha)
    repo_root = repo_root.resolve()
    watchdog_source = repo_root / "scripts" / "noteri_control_plane_watchdog.py"
    if not watchdog_source.is_file():
        raise LauncherError("watchdog fonte ausente no checkout")

    metadata = load_metadata(metadata_path)
    runner_home = Path(str(metadata["runner_home"])).resolve()

    current = task_status()
    if task_headless_ready(current):
        attest_installed_release(metadata, source_sha, watchdog_source)
        finalized = finalize(metadata_path, current)
        return {
            "ok": True,
            "mode": "already_ready",
            "result": "NOTERI_CONTROL_PLANE_HEADLESS_READY",
            "task": current,
            "rdc_required": False,
            "production_touched": False,
            "reboot_performed": False,
            **finalized,
        }

    elevated_result_path = watchdog.runtime_root() / "elevated-install-result.json"
    try:
        elevated_result_path.unlink()
    except FileNotFoundError:
        pass

    broker = "already_elevated" if is_admin() else "none"

    if is_admin():
        result = subprocess.run(
            [
                sys.executable,
                str(watchdog_source),
                "install",
                "--repo-root",
                str(repo_root),
                "--runner-home",
                str(runner_home),
                "--source-sha",
                source_sha,
                "--confirm",
                watchdog.INSTALL_CONFIRM,
                "--result-path",
                str(elevated_result_path),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            raise LauncherError(f"watchdog_install_failed:{result.returncode}")
    else:
        params = build_install_args(
            repo_root=repo_root,
            runner_home=runner_home,
            source_sha=source_sha,
            result_path=elevated_result_path,
        )
        rc = shell_execute_runas(Path(sys.executable), params, repo_root)
        if rc > 32:
            broker = "shell_execute_runas"
        elif powershell_runas(Path(sys.executable), params, repo_root):
            broker = "powershell_start_process_runas"
        elif shell_application_runas(Path(sys.executable), params, repo_root):
            broker = "shell_application_runas"
        else:
            raise LauncherError(f"uac_launch_failed:{rc}")

    deadline = time.monotonic() + max(15, min(timeout_seconds, 240))
    last = current
    elevated_result: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if elevated_result_path.is_file():
            try:
                elevated_result = json.loads(elevated_result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                elevated_result = None
            if elevated_result and elevated_result.get("ok") is False:
                return {
                    "ok": False,
                    "mode": "elevated" if is_admin() else "uac",
                    "result": "ELEVATED_INSTALL_FAILED",
                    "elevated_result": {
                        "ok": False,
                        "error": str(elevated_result.get("error") or "")[:1000],
                        "error_type": str(elevated_result.get("error_type") or ""),
                    },
                    "task": task_status(),
                    "rdc_required": False,
                    "production_touched": False,
                    "reboot_performed": False,
                }
        last = task_status()
        if task_headless_ready(last):
            attest_installed_release(load_metadata(metadata_path), source_sha, watchdog_source)
            finalized = finalize(metadata_path, last)
            return {
                "ok": True,
                "mode": "elevated" if is_admin() else "uac",
                "uac_broker": broker,
                "result": "NOTERI_CONTROL_PLANE_HEADLESS_PROVISIONED",
                "task": last,
                "rdc_required": False,
                "production_touched": False,
                "reboot_performed": False,
                **finalized,
            }
        time.sleep(1)

    return {
        "ok": False,
        "mode": "uac",
        "uac_broker": broker,
        "result": "UAC_APPROVAL_OR_PROVISIONING_PENDING",
        "task": last,
        "elevated_result_observed": bool(elevated_result),
        "rdc_required": False,
        "production_touched": False,
        "reboot_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--metadata", type=Path, default=watchdog.metadata_path())
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    try:
        payload = launch(
            repo_root=args.repo_root,
            source_sha=args.source_sha,
            metadata_path=args.metadata,
            confirm=args.confirm,
            timeout_seconds=args.timeout_seconds,
        )
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        watchdog.WatchdogError,
        LauncherError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc)[:1000],
                    "error_type": type(exc).__name__,
                    "rdc_required": False,
                    "production_touched": False,
                    "reboot_performed": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
