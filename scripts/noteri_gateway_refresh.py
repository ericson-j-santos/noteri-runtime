#!/usr/bin/env python3
"""Atualização elevada e fail-closed do Command Gateway no host Noteri."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

EXPECTED_HOST = "Noteri"
EXPECTED_WORKFLOW_REPOSITORY = "ericson-j-santos/noteri-runtime"
CONFIRM = "REFRESH-NOTERI-COMMAND-GATEWAY"
RULES_REPO = "ericson-j-santos/chatgpt-operational-rules"
RULES_COMMIT = "92e927757c29396228d7c2a04bd3a0ebac21422c"
RULES_VERSION = "1.6.11"
INSTALL_SHA256 = "f73d843c86953e5f1eaca791850b5b10ccb670389cef722c2b7d921ff381f561"
UPDATE_SHA256 = "fbed2c036415a4f97637c453c37e3060a580d549f68a519785d0a02926589103"
INSTALL_ROOT = Path(r"C:\dev\chatgpt-command-gateway")
WORK_ROOT = Path(r"C:\dev\chatgpt-workers")
MANAGED_FILES = {
    "bin/command_gateway.py",
    "bin/host_health_check.py",
    "bin/session_bootstrap.py",
    "bin/session_preflight.py",
    "bin/session_launcher.py",
    "bin/runner_version_preflight.py",
    "config/policy.json",
}
HEAD_RE = re.compile(r"^[0-9a-f]{40}$")


class RefreshError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(host: str, confirm: str, commit: str) -> None:
    if host.casefold() != EXPECTED_HOST.casefold():
        raise RefreshError("host invalido")
    if confirm != CONFIRM:
        raise RefreshError("confirmacao invalida")
    if commit != RULES_COMMIT:
        raise RefreshError("commit divergente")


def validate_execution(
    repository: str, workflow_sha: str, run_id: int, run_attempt: int
) -> None:
    if repository != EXPECTED_WORKFLOW_REPOSITORY:
        raise RefreshError("repositorio do workflow divergente")
    if not HEAD_RE.fullmatch(workflow_sha):
        raise RefreshError("sha do workflow invalido")
    if run_id < 1 or run_attempt < 1:
        raise RefreshError("identidade da execucao invalida")


def is_admin() -> bool:
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def fetch(path: str, expected: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{RULES_REPO}/{RULES_COMMIT}/scripts/{path}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "Noteri-Gateway-Refresh/1"}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(256 * 1024)
    if sha256(data) != expected:
        raise RefreshError(f"hash divergente: {path}")
    return data


def atomic_json(path: Path, payload: dict) -> None:
    raw = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + f".tmp-{uuid.uuid4().hex}")
    temporary.write_bytes(raw)
    try:
        os.replace(temporary, path)
    except OSError:
        try:
            if (
                temporary.is_file()
                and not temporary.is_symlink()
                and temporary.read_bytes() == raw
            ):
                temporary.unlink()
        except OSError:
            pass
        raise


def load_update_receipt() -> dict | None:
    path = INSTALL_ROOT / "update-receipt.json"
    if not path.is_file():
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RefreshError("recibo de update invalido") from exc
    if not isinstance(receipt, dict):
        raise RefreshError("recibo de update invalido")
    return receipt


def verify_update_receipt(receipt: dict) -> dict[str, dict]:
    if (
        receipt.get("result") != "HOST_UPDATE_OK"
        or receipt.get("source_commit") != RULES_COMMIT
        or receipt.get("rules_version") != RULES_VERSION
        or str(receipt.get("host", "")).casefold() != EXPECTED_HOST.casefold()
        or receipt.get("validation_head") != RULES_COMMIT
        or os.path.normcase(str(receipt.get("install_root", "")))
        != os.path.normcase(str(INSTALL_ROOT))
    ):
        raise RefreshError("contrato do recibo de update divergente")

    backup_dir = Path(str(receipt.get("backup_dir", "")))
    if not backup_dir.is_dir() or not (backup_dir / "rollback-manifest.json").is_file():
        raise RefreshError("backup de rollback nao comprovado")

    files = receipt.get("files")
    if not isinstance(files, dict) or set(files) != MANAGED_FILES:
        raise RefreshError("conjunto de arquivos do recibo divergente")
    verified: dict[str, dict] = {}
    for relative in sorted(MANAGED_FILES):
        metadata = files.get(relative)
        target = INSTALL_ROOT.joinpath(*relative.split("/"))
        if (
            not isinstance(metadata, dict)
            or target.is_symlink()
            or not target.is_file()
        ):
            raise RefreshError(f"arquivo instalado nao comprovado: {relative}")
        observed = {
            "sha256": sha256_file(target),
            "size": target.stat().st_size,
        }
        if (
            metadata.get("sha256") != observed["sha256"]
            or metadata.get("size") != observed["size"]
        ):
            raise RefreshError(f"hash instalado divergente: {relative}")
        verified[relative] = observed
    return verified


def bind_execution(receipt: dict, *, repository: str, workflow_sha: str,
                   run_id: int, run_attempt: int) -> dict:
    verified = verify_update_receipt(receipt)
    bound = dict(receipt)
    bound.update(
        {
            "workflow_repository": repository,
            "workflow_sha": workflow_sha,
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
            "files": verified,
        }
    )
    atomic_json(INSTALL_ROOT / "update-receipt.json", bound)
    return bound


def run_elevated(
    confirm: str,
    commit: str,
    *,
    repository: str,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict:
    validate(socket.gethostname(), confirm, commit)
    validate_execution(repository, workflow_sha, run_id, run_attempt)
    if not is_admin():
        raise RefreshError("elevacao obrigatoria antes do refresh")

    current = load_update_receipt()
    if (
        current is not None
        and current.get("result") == "HOST_UPDATE_OK"
        and current.get("source_commit") == RULES_COMMIT
        and current.get("rules_version") == RULES_VERSION
    ):
        bind_execution(
            current,
            repository=repository,
            workflow_sha=workflow_sha,
            run_id=run_id,
            run_attempt=run_attempt,
        )
        return {
            "ok": True,
            "result": "NOTERI_GATEWAY_ALREADY_CURRENT",
            "source_commit": RULES_COMMIT,
            "rules_version": RULES_VERSION,
        }

    install = fetch("install_command_gateway_host.py", INSTALL_SHA256)
    update = fetch("update_command_gateway_host.py", UPDATE_SHA256)
    with tempfile.TemporaryDirectory(prefix="noteri-gateway-refresh-") as temp:
        root = Path(temp)
        (root / "install_command_gateway_host.py").write_bytes(install)
        updater = root / "update_command_gateway_host.py"
        updater.write_bytes(update)
        command = [
            sys.executable,
            str(updater),
            "--commit",
            RULES_COMMIT,
            "--expected-self-sha256",
            UPDATE_SHA256,
            "--install-root",
            str(INSTALL_ROOT),
            "--work-root",
            str(WORK_ROOT),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if result.returncode != 0:
            raise RefreshError(
                f"updater_failed:{result.returncode}:{result.stderr[-500:]}"
            )

    receipt = load_update_receipt()
    if receipt is None:
        raise RefreshError("recibo de update ausente")
    bind_execution(
        receipt,
        repository=repository,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    return {
        "ok": True,
        "result": "NOTERI_GATEWAY_REFRESHED",
        "source_commit": RULES_COMMIT,
        "rules_version": RULES_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--commit", default=RULES_COMMIT)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    args = parser.parse_args()
    try:
        output = run_elevated(
            args.confirm,
            args.commit,
            repository=args.workflow_repository,
            workflow_sha=args.workflow_sha,
            run_id=args.workflow_run_id,
            run_attempt=args.workflow_run_attempt,
        )
    except Exception as exc:
        output = {
            "ok": False,
            "result": "NOTERI_GATEWAY_REFRESH_BLOCKED",
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
        }
    print(json.dumps(output, sort_keys=True))
    return 0 if output.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())
