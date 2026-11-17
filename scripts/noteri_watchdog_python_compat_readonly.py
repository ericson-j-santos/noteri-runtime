#!/usr/bin/env python3
"""Sonda Risk1: verifica pywin32 no Python da tarefa watchdog, sem alteracao."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import ntpath
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CONFIRM = "CHECK-NOTERI-TASK-PYTHON-READONLY"
OLD_SHA = "cc06e6530ca57058db22651ac75d623f6ec921c1"
OLD_DIGEST = "090728ba5f52360654cacac6bf44366fb6e03c7016ddea763ce62c425c2f76a0"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


class Blocked(RuntimeError):
    pass


def sha256(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise Blocked("EXECUTABLE_UNAVAILABLE")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def importable() -> bool:
    try:
        importlib.import_module("win32com.client")
        importlib.import_module("pythoncom")
        return True
    except Exception:
        return False


def task_command(xml: str) -> str:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise Blocked("TASK_XML_INVALID") from exc
    actions = root.findall("./t:Actions/*", NS)
    if len(actions) != 1 or not actions[0].tag.endswith("}Exec"):
        raise Blocked("TASK_ACTION_INVALID")
    exe = (actions[0].findtext("t:Command", namespaces=NS) or "").strip().strip('"')
    if ntpath.basename(exe).casefold() not in {"python.exe", "python3.exe"}:
        raise Blocked("TASK_PYTHON_UNEXPECTED")
    return exe


def read_task(watchdog, inventory) -> tuple[str, str]:
    result = subprocess.run(
        [str(watchdog.schtasks_path()), "/Query", "/TN", watchdog.TASK_NAME, "/XML"],
        capture_output=True, timeout=20, check=False,
    )
    if result.returncode != 0:
        raise Blocked("TASK_QUERY_FAILED")
    return inventory.decode_task_xml_strict(result.stdout), hashlib.sha256(result.stdout).hexdigest()


def child(expected_source: str, expected_exe: str) -> int:
    if sha256(Path(__file__)) != expected_source or sha256(Path(sys.executable)) != expected_exe:
        raise Blocked("CHILD_HASH_MISMATCH")
    print(json.dumps({"result": "TASK_PYTHON_CHECKED",
                      "source_sha256": expected_source, "python_sha256": expected_exe,
                      "pywin32_importable": importable()}, sort_keys=True))
    return 0


def upgrade_preflight_using_task_python(repo: Path, exe: Path, executable_sha: str,
                                       expected_head: str, correlation: str,
                                       safe_env: dict[str, str]) -> str:
    """Roda somente o preflight do upgrade no Python S4U ja atestado.

    Entrada, script e caminho sao fixados pelo checkout e pela Task XML.
    Nao existe parametro de comando arbitrario nem modo de atualizacao.
    """
    script = repo / "scripts" / "noteri_watchdog_transactional_upgrade.py"
    source = repo / "scripts" / "noteri_control_plane_watchdog.py"
    if not script.is_file() or not source.is_file():
        raise Blocked("UPGRADE_PREFLIGHT_SOURCE_MISSING")
    script_sha = sha256(script)
    source_sha = sha256(source)
    args = [
        str(exe), "-B", str(script),
        "--repo-root", str(repo),
        "--old-sha", OLD_SHA, "--old-digest", OLD_DIGEST,
        "--target-sha", expected_head, "--target-digest", source_sha,
        "--correlation-id", correlation, "--mode", "preflight",
    ]
    try:
        finished = subprocess.run(
            args, cwd=str(repo), env=safe_env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=35, check=False,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("UPGRADE_PREFLIGHT_EXECUTION_FAILED") from exc
    if len(finished.stdout) > 4096 or len(finished.stdout) == 0:
        raise Blocked("UPGRADE_PREFLIGHT_RESPONSE_INVALID")
    try:
        value = json.loads(finished.stdout.strip())
    except ValueError as exc:
        raise Blocked("UPGRADE_PREFLIGHT_RESPONSE_INVALID") from exc
    if not isinstance(value, dict) or value.get("state_changed") is not False:
        raise Blocked("UPGRADE_PREFLIGHT_RESPONSE_INVALID")
    if sha256(exe) != executable_sha or sha256(script) != script_sha or sha256(source) != source_sha:
        raise Blocked("UPGRADE_PREFLIGHT_BYTES_CHANGED")
    if finished.returncode == 0 and value.get("result") == "PREFLIGHT_OK_NOT_AUTHORIZED":
        if value.get("target_sha") != expected_head or value.get("old_sha") != OLD_SHA:
            raise Blocked("UPGRADE_PREFLIGHT_RESPONSE_INVALID")
        return "PREFLIGHT_OK_NOT_AUTHORIZED"
    if finished.returncode != 0 and value.get("result") == "BLOCKED":
        reason = value.get("reason")
        if isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{3,75}", reason):
            return "BLOCKED_" + reason
    return "BLOCKED_UNEXPECTED_RESPONSE"


def check(expected_head: str, correlation: str, confirmation: str, *, probe_upgrade: bool = False) -> dict:
    if confirmation != CONFIRM or not SHA_RE.fullmatch(expected_head):
        raise Blocked("ADMISSION_INVALID")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", correlation):
        raise Blocked("CORRELATION_INVALID")
    repo = Path(__file__).resolve().parents[1]
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    if head != expected_head:
        raise Blocked("WORKTREE_SHA_MISMATCH")
    import noteri_control_plane_watchdog as watchdog
    import noteri_control_plane_watchdog_uac_launcher as launcher
    import noteri_watchdog_readonly_inventory as inventory
    meta = inventory.safe_metadata(watchdog.metadata_path())
    if meta.get("source_sha") != OLD_SHA or meta.get("release_sha256") != OLD_DIGEST:
        raise Blocked("INSTALLED_VERSION_CHANGED")
    receipt = inventory.read_installed_release_receipt(meta)
    xml, task_digest = read_task(watchdog, inventory)
    if not receipt["task_action_verified"] or receipt["task_definition_sha256"] != task_digest:
        raise Blocked("TASK_ATTESTATION_MISMATCH")
    path = Path(task_command(xml))
    if not path.is_absolute() or launcher._path_is_redirect(path):
        raise Blocked("TASK_PYTHON_UNTRUSTED")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Blocked("TASK_PYTHON_NOT_FOUND") from exc
    if os.path.normcase(str(resolved)) != os.path.normcase(str(path)):
        raise Blocked("TASK_PYTHON_UNTRUSTED")
    binary_sha = sha256(resolved)
    source_sha = sha256(Path(__file__))
    safe_env = {k: os.environ[k] for k in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP") if k in os.environ}
    safe_env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            [str(resolved), "-I", "-B", str(Path(__file__).resolve()),
             "--child", "--child-source", source_sha, "--child-python", binary_sha],
            cwd=str(repo), env=safe_env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=20, check=False,
            shell=False, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise Blocked("TASK_PYTHON_PROBE_FAILED") from exc
    if proc.returncode != 0 or len(proc.stdout) > 2048:
        raise Blocked("TASK_PYTHON_PROBE_FAILED")
    try:
        value = json.loads(proc.stdout.strip())
    except ValueError as exc:
        raise Blocked("TASK_PYTHON_RESPONSE_INVALID") from exc
    if (not isinstance(value, dict) or
        set(value) != {"result", "source_sha256", "python_sha256", "pywin32_importable"} or
        value["result"] != "TASK_PYTHON_CHECKED" or
        value["source_sha256"] != source_sha or value["python_sha256"] != binary_sha or
        type(value["pywin32_importable"]) is not bool):
        raise Blocked("TASK_PYTHON_RESPONSE_INVALID")
    _, after_digest = read_task(watchdog, inventory)
    if after_digest != task_digest or sha256(resolved) != binary_sha:
        raise Blocked("TASK_OR_BINARY_CHANGED")
    available = value["pywin32_importable"]
    preflight = "NOT_REQUESTED"
    if probe_upgrade:
        preflight = (
            upgrade_preflight_using_task_python(repo, resolved, binary_sha, expected_head, correlation, safe_env)
            if available else "SKIPPED_PYWIN32_UNAVAILABLE"
        )
    return {
        "schema": 1, "result": "PYWIN32_READY" if available else "PYWIN32_NOT_IMPORTABLE",
        "expected_sha": expected_head, "correlation_id": correlation,
        "task_sha256": task_digest, "task_python_sha256": binary_sha,
        "gateway_python_sha256": sha256(Path(sys.executable)),
        "same_interpreter": os.path.normcase(str(resolved)) == os.path.normcase(str(Path(sys.executable).resolve())),
        "task_pywin32_importable": available, "gateway_pywin32_importable": importable(),
        "profile": watchdog.runtime_profile(), "task_s4u_verified": True,
        "upgrade_preflight": preflight,
        "state_changed": False, "installation_authorized": False,
        "production_touched": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-head", default="")
    p.add_argument("--correlation-id", default="")
    p.add_argument("--confirm", default="")
    p.add_argument("--child", action="store_true")
    p.add_argument("--child-source", default="")
    p.add_argument("--child-python", default="")
    p.add_argument("--probe-upgrade", action="store_true")
    args = p.parse_args()
    try:
        if os.name != "nt" or socket.gethostname().casefold() != "noteri" or not sys.dont_write_bytecode:
            raise Blocked("HOST_OR_RUNTIME_INVALID")
        if args.child:
            if not DIGEST_RE.fullmatch(args.child_source) or not DIGEST_RE.fullmatch(args.child_python):
                raise Blocked("CHILD_DIGEST_INVALID")
            return child(args.child_source, args.child_python)
        print(json.dumps(check(args.expected_head, args.correlation_id, args.confirm,
                               probe_upgrade=args.probe_upgrade), sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Blocked) else "PYTHON_COMPAT_CHECK_FAILED"
        print(json.dumps({"result": "BLOCKED", "reason": reason if re.fullmatch(r"[A-Z][A-Z0-9_]{3,79}", reason) else "PYTHON_COMPAT_CHECK_FAILED",
                          "state_changed": False, "installation_authorized": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
