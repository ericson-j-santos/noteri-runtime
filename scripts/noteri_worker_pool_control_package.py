#!/usr/bin/env python3
"""Prepare pinned pywin32 in a private target for Task Scheduler COM registration."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import site
import socket
import subprocess
import sys
import uuid
from pathlib import Path

from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_native_venv as venv

CONFIRM = "PREPARE-NOTERI-WORKER-POOL-COM"
REQUIREMENT = ("pywin32==312 --hash=sha256:"
               "a4dd3a848290ef724347b19f301045831d8e802fa4464f491b98b1e0a081432e")
TARGET_NAME = "pywin32-312-cp314"


class Blocked(RuntimeError):
    pass


def paths(local: Path) -> tuple[Path, Path]:
    root, _, _ = venv._paths(local)
    return root, root / "control" / TARGET_NAME


def qualify(local: Path, source: Path) -> tuple[Path, Path]:
    if (os.name != "nt" or socket.gethostname().casefold() != "noteri"
            or sys.version_info[:2] != (3, 14)
            or ctypes.sizeof(ctypes.c_void_p) != 8):
        raise Blocked("host_or_python")
    profile = json.loads((local / reference.PROFILE_RELATIVE).read_text(encoding="utf-8"))
    if profile.get("profile") != "NORMAL":
        raise Blocked("profile")
    requirement = source / "noteri_worker_pool_control_requirements.txt"
    if requirement.read_text(encoding="utf-8").strip() != REQUIREMENT:
        raise Blocked("requirements")
    root, target = paths(local)
    stage.ensure_no_link_components(root)
    return root, target


def verify(target: Path) -> bool:
    try:
        stage.ensure_no_link_components(target)
        required = ("win32com/client/__init__.py", "pywin32.pth",
                    "pywin32-312.dist-info/METADATA",
                    "pywin32_system32/pythoncom314.dll",
                    "pywin32_system32/pywintypes314.dll")
        if not target.is_dir() or any(not (target / name).is_file() for name in required):
            return False
        metadata = (target / required[2]).read_text(encoding="utf-8")
        if "Name: pywin32\n" not in metadata.replace("\r\n", "\n") or "Version: 312\n" not in metadata.replace("\r\n", "\n"):
            return False
        site.addsitedir(str(target))
        import win32com.client  # type: ignore
        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        return service.GetFolder(r"\Automation") is not None
    except Exception:
        return False


def _remove_owned(path: Path, root: Path) -> None:
    if not path.exists():
        return
    if not path.resolve().is_relative_to(root.resolve()):
        raise Blocked("cleanup_scope")
    stage.ensure_no_link_components(path)
    shutil.rmtree(path)


def prepare(local: Path, source: Path) -> str:
    root, target = qualify(local, source)
    if target.exists():
        return "ALREADY_PREPARED" if verify(target) else "BLOCKED_EXISTING"
    control = target.parent
    stage.ensure_no_link_components(control)
    control.mkdir(exist_ok=True)
    staging = control / f".{TARGET_NAME}-{uuid.uuid4().hex}.tmp"
    created_target = False
    try:
        completed = subprocess.run([
            sys.executable, "-B", "-m", "pip", "install", "--no-deps",
            "--require-hashes", "--target", str(staging), "-r",
            str(source / "noteri_worker_pool_control_requirements.txt")],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=180, check=False)
        if completed.returncode != 0 or not verify(staging):
            raise Blocked("package_install")
        staging.rename(target)
        created_target = True
        if not verify(target):
            raise Blocked("package_readback")
        return "CONTROL_PACKAGE_PREPARED"
    except Exception:
        _remove_owned(staging, root)
        if created_target:
            _remove_owned(target, root)
        return "BLOCKED_PREPARE"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "prepare", "verify"), default="plan")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    try:
        local = Path(os.environ["LOCALAPPDATA"])
        source = Path(__file__).resolve().parent
        root, target = qualify(local, source)
        if args.mode == "verify":
            result = "CONTROL_PACKAGE_READY" if verify(target) else "BLOCKED_PACKAGE"
        elif args.mode == "plan":
            result = ("ALREADY_PREPARED" if verify(target) else "BLOCKED_EXISTING") if target.exists() else "CONTROL_PACKAGE_PREPARE_READY"
        elif args.confirm != CONFIRM:
            result = "BLOCKED_ACTION"
        else:
            result = prepare(local, source)
    except Exception:
        result = "BLOCKED_PRECONDITION"
    print(json.dumps({"schema_version": "1", "result": result}, sort_keys=True))
    return 0 if result in {"CONTROL_PACKAGE_PREPARE_READY", "CONTROL_PACKAGE_PREPARED",
                           "CONTROL_PACKAGE_READY", "ALREADY_PREPARED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
