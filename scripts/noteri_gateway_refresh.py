#!/usr/bin/env python3
"""Atualiza��o elevada e fail-closed do Command Gateway no host Noteri."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_HOST = "Noteri"
EXPECTED_WORKFLOW_REPOSITORY = "ericson-j-santos/noteri-runtime"
CONFIRM = "REFRESH-NOTERI-COMMAND-GATEWAY"
RULES_REPO = "ericson-j-santos/chatgpt-operational-rules"
RULES_COMMIT = "b5ade370fa11877ff7b899b5c6feacc3bfaf34e7"
RULES_VERSION = "1.6.19"
MANIFEST_SHA256 = "fbf4af678a11111b8a895bee1f19211523f0bdcb292838f64e252ab67d37f96c"
INSTALL_SHA256 = "4b2c200680de7e0db6bd44905a246d7e1773b36d0f516d9756046e758827e35a"
UPDATE_SHA256 = "fa5d03b0cecb46cf02477af4a75c81c57b92d7b609d4bd4abd54f28a7b22b1a2"
LEGACY_VERIFY_SHA256 = "b792692d6c86bccccfba9037596d3a7cbd4996e7d560f257194efa020357bef4"
INSTALL_ROOT = Path(r"C:\dev\chatgpt-command-gateway")
WORK_ROOT = Path(r"C:\dev\chatgpt-workers")
RUN_RECEIPT_NAME = "refresh-run-receipt.json"
RUNTIME_MAP = {
    "scripts/command_gateway.py": "bin/command_gateway.py",
    "scripts/host_health_check.py": "bin/host_health_check.py",
    "scripts/session_bootstrap.py": "bin/session_bootstrap.py",
    "scripts/session_preflight.py": "bin/session_preflight.py",
    "scripts/session_launcher.py": "bin/session_launcher.py",
    "scripts/runner_version_preflight.py": "bin/runner_version_preflight.py",
    "config/command-gateway.policy.noteri-wsl.json": "config/policy.json",
}
MANAGED_FILES = set(RUNTIME_MAP.values())
HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise RefreshError("timestamp do recibo invalido")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RefreshError("timestamp do recibo invalido") from exc
    if parsed.tzinfo is None:
        raise RefreshError("timestamp do recibo sem timezone")
    return parsed.astimezone(timezone.utc)


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


def fetch(relative: str, expected: str, max_bytes: int = 512 * 1024) -> bytes:
    url = f"https://raw.githubusercontent.com/{RULES_REPO}/{RULES_COMMIT}/{relative}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "Noteri-Gateway-Refresh/1"}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RefreshError(f"download excede limite: {relative}")
    if sha256(data) != expected:
        raise RefreshError(f"hash divergente: {relative}")
    return data


def canonical_files(payload: bytes) -> dict[str, dict]:
    try:
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RefreshError("manifesto canonico invalido") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != RULES_VERSION
        or not isinstance(manifest.get("files"), list)
    ):
        raise RefreshError("contrato do manifesto canonico divergente")
    index: dict[str, dict] = {}
    for item in manifest["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise RefreshError("entrada do manifesto canonico invalida")
        path = item["path"]
        if path in index:
            raise RefreshError(f"entrada canonica duplicada: {path}")
        index[path] = item
    expected: dict[str, dict] = {}
    for source, destination in RUNTIME_MAP.items():
        entry = index.get(source)
        if not isinstance(entry, dict):
            raise RefreshError(f"arquivo canonico ausente: {source}")
        digest = str(entry.get("sha256", "")).lower()
        size = entry.get("size")
        if (
            not SHA256_RE.fullmatch(digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise RefreshError(f"metadado canonico invalido: {source}")
        expected[destination] = {
            "source": source,
            "sha256": digest,
            "size": size,
        }
    return expected


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


def read_update_receipt() -> tuple[dict, bytes] | None:
    path = INSTALL_ROOT / "update-receipt.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        raw = path.read_bytes()
        receipt = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RefreshError("recibo de update invalido") from exc
    if not isinstance(receipt, dict):
        raise RefreshError("recibo de update invalido")
    return receipt, raw


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(
        str(right.resolve())
    )


def _is_reparse_point(path_stat: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(path_stat, "st_file_attributes", 0) & reparse_flag)


def _confined_existing(
    root: Path, relative: str, *, label: str, require_directory: bool
) -> Path:
    """Resolve an existing path without traversing links or reparse points."""
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise RefreshError(f"raiz ausente: {label}") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or _is_reparse_point(root_stat)
        or not stat.S_ISDIR(root_stat.st_mode)
    ):
        raise RefreshError(f"raiz insegura: {label}")
    resolved_root = root.resolve()
    current = root
    parts = relative.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RefreshError(f"caminho relativo invalido: {label}")
    for index, part in enumerate(parts):
        current = current / part
        try:
            observed = os.lstat(current)
        except OSError as exc:
            raise RefreshError(f"componente ausente: {label}") from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse_point(observed):
            raise RefreshError(f"componente reparse inseguro: {label}")
        if index < len(parts) - 1 and not stat.S_ISDIR(observed.st_mode):
            raise RefreshError(f"componente intermediario invalido: {label}")
        resolved = current.resolve()
        try:
            common = os.path.commonpath([str(resolved_root), str(resolved)])
        except ValueError as exc:
            raise RefreshError(f"caminho fora da raiz: {label}") from exc
        if os.path.normcase(common) != os.path.normcase(str(resolved_root)):
            raise RefreshError(f"caminho fora da raiz: {label}")
    if require_directory:
        if not stat.S_ISDIR(observed.st_mode):
            raise RefreshError(f"diretorio ausente: {label}")
    elif not stat.S_ISREG(observed.st_mode):
        raise RefreshError(f"arquivo regular ausente: {label}")
    return current


def confined_regular_file(root: Path, relative: str, *, label: str) -> Path:
    return _confined_existing(
        root, relative, label=label, require_directory=False
    )


def confined_directory(root: Path, relative: str, *, label: str) -> Path:
    return _confined_existing(
        root, relative, label=label, require_directory=True
    )


def verify_absent_confined(root: Path, relative: str, *, label: str) -> None:
    """Require an absent leaf while rejecting any existing unsafe component."""
    root_stat = os.lstat(root)
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or _is_reparse_point(root_stat)
        or not stat.S_ISDIR(root_stat.st_mode)
    ):
        raise RefreshError(f"raiz insegura: {label}")
    resolved_root = root.resolve()
    current = root
    parts = relative.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise RefreshError(f"caminho relativo invalido: {label}")
    for index, part in enumerate(parts):
        current = current / part
        try:
            observed = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise RefreshError(f"componente ilegivel: {label}") from exc
        if stat.S_ISLNK(observed.st_mode) or _is_reparse_point(observed):
            raise RefreshError(f"componente reparse inseguro: {label}")
        resolved = current.resolve()
        common = os.path.commonpath([str(resolved_root), str(resolved)])
        if os.path.normcase(common) != os.path.normcase(str(resolved_root)):
            raise RefreshError(f"caminho fora da raiz: {label}")
        if index < len(parts) - 1 and not stat.S_ISDIR(observed.st_mode):
            raise RefreshError(f"componente intermediario invalido: {label}")
    raise RefreshError(f"backup inesperado para arquivo novo: {label}")


def verify_rollback(backup_dir: Path, expected: dict[str, dict]) -> str:
    root = INSTALL_ROOT.resolve()
    backup = backup_dir.resolve()
    try:
        confined = os.path.commonpath([str(root), str(backup)])
    except ValueError as exc:
        raise RefreshError("backup fora da instalacao") from exc
    if os.path.normcase(confined) != os.path.normcase(str(root)) or backup == root:
        raise RefreshError("backup fora da instalacao")
    try:
        backup_stat = os.lstat(backup_dir)
    except OSError as exc:
        raise RefreshError("diretorio de rollback invalido") from exc
    if (
        stat.S_ISLNK(backup_stat.st_mode)
        or _is_reparse_point(backup_stat)
        or not stat.S_ISDIR(backup_stat.st_mode)
    ):
        raise RefreshError("diretorio de rollback invalido")
    manifest_path = confined_regular_file(
        backup_dir, "rollback-manifest.json", label="manifesto de rollback"
    )
    try:
        snapshot = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RefreshError("manifesto de rollback invalido") from exc
    if (not isinstance(snapshot, dict) or snapshot.get("version") != 2
            or snapshot.get("metadata_contract") != "windows-owner-group-dacl-ads-v1"):
        raise RefreshError("schema do rollback invalido")
    snapshot_root = snapshot.get("install_root")
    if not isinstance(snapshot_root, str) or not _same_path(Path(snapshot_root), root):
        raise RefreshError("raiz do rollback divergente")
    entries = snapshot.get("entries")
    if not isinstance(entries, dict) or set(entries) != MANAGED_FILES:
        raise RefreshError("conjunto gerenciado do rollback divergente")
    for destination, canonical in expected.items():
        entry = entries.get(destination)
        if not isinstance(entry, dict) or not isinstance(entry.get("existed"), bool):
            raise RefreshError(f"entrada de rollback invalida: {destination}")
        if (
            entry.get("source") != canonical["source"]
            or entry.get("desired_sha256") != canonical["sha256"]
            or entry.get("desired_size") != canonical["size"]
        ):
            raise RefreshError(f"rollback nao pertence ao bundle: {destination}")
        previous = backup_dir.joinpath("files", *destination.split("/"))
        if entry["existed"]:
            if not isinstance(entry.get("previous_windows_state"), dict):
                raise RefreshError(f"metadados Windows ausentes: {destination}")
            digest = str(entry.get("previous_sha256", "")).lower()
            size = entry.get("previous_size")
            mode = entry.get("previous_mode")
            if (
                not SHA256_RE.fullmatch(digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or isinstance(mode, bool)
                or not isinstance(mode, int)
                or mode < 0
            ):
                raise RefreshError(f"metadado de backup invalido: {destination}")
            previous = confined_regular_file(
                backup_dir,
                "files/" + destination,
                label=f"arquivo de backup: {destination}",
            )
            observed = previous.stat()
            if (
                sha256_file(previous) != digest
                or observed.st_size != size
                or stat.S_IMODE(observed.st_mode) != mode
            ):
                raise RefreshError(f"arquivo de backup divergente: {destination}")
        else:
            verify_absent_confined(
                backup_dir,
                "files/" + destination,
                label=destination,
            )
    return sha256_file(manifest_path)


def verify_update_receipt(
    receipt: dict, expected: dict[str, dict]
) -> dict[str, object]:
    if (
        receipt.get("result") != "HOST_UPDATE_OK"
        or receipt.get("source_commit") != RULES_COMMIT
        or receipt.get("rules_version") != RULES_VERSION
        or receipt.get("noteri_wsl_inventory_profile") is not True
        or str(receipt.get("host", "")).casefold() != EXPECTED_HOST.casefold()
        or receipt.get("validation_head") != RULES_COMMIT
        or not _same_path(Path(str(receipt.get("install_root", ""))), INSTALL_ROOT)
    ):
        raise RefreshError("contrato do recibo de update divergente")
    updated_at = parse_utc(receipt.get("updated_at"))
    files = receipt.get("files")
    if not isinstance(files, dict) or set(files) != MANAGED_FILES:
        raise RefreshError("conjunto de arquivos do recibo divergente")
    verified: dict[str, dict] = {}
    for relative, canonical in expected.items():
        metadata = files.get(relative)
        if not isinstance(metadata, dict):
            raise RefreshError(f"arquivo instalado nao comprovado: {relative}")
        target = confined_regular_file(
            INSTALL_ROOT, relative, label=f"arquivo instalado: {relative}"
        )
        observed = {"sha256": sha256_file(target), "size": target.stat().st_size}
        if (
            metadata.get("sha256") != canonical["sha256"]
            or metadata.get("size") != canonical["size"]
            or observed["sha256"] != canonical["sha256"]
            or observed["size"] != canonical["size"]
        ):
            raise RefreshError(f"arquivo instalado diverge da fonte canonica: {relative}")
        verified[relative] = observed
    backup_dir = Path(str(receipt.get("backup_dir", "")))
    rollback_hash = verify_rollback(backup_dir, expected)
    return {
        "files": verified,
        "backup_dir": str(backup_dir),
        "rollback_manifest_sha256": rollback_hash,
        "updated_at": updated_at,
    }


def write_run_receipt(
    *, outcome: str, installation_performed: bool, source_receipt: dict,
    source_raw: bytes, evidence: dict[str, object], repository: str,
    workflow_sha: str, run_id: int, run_attempt: int,
) -> dict:
    bound = {
        "result": outcome,
        "installation_performed_by_run": installation_performed,
        "verified_at": utc_now(),
        "host": EXPECTED_HOST,
        "source_commit": RULES_COMMIT,
        "rules_version": RULES_VERSION,
        "noteri_wsl_inventory_profile": True,
        "install_root": str(INSTALL_ROOT),
        "validation_head": source_receipt["validation_head"],
        "source_receipt_updated_at": source_receipt["updated_at"],
        "source_receipt_sha256": sha256(source_raw),
        "backup_dir": evidence["backup_dir"],
        "rollback_manifest_sha256": evidence["rollback_manifest_sha256"],
        "files": evidence["files"],
        "workflow_repository": repository,
        "workflow_sha": workflow_sha,
        "workflow_run_id": run_id,
        "workflow_run_attempt": run_attempt,
    }
    atomic_json(INSTALL_ROOT / RUN_RECEIPT_NAME, bound)
    return bound


def run_elevated(
    confirm: str, commit: str, *, repository: str, workflow_sha: str,
    run_id: int, run_attempt: int,
    legacy_receipt_sha256: str | None = None,
    legacy_manifest_sha256: str | None = None,
) -> dict:
    """Legacy entrypoint name; invokes only the canonical updater with explicit pins.

    No UAC or privilege escalation is attempted. The updater's replaceability
    preflight decides whether the existing runner identity may replace files.
    """
    validate(socket.gethostname(), confirm, commit)
    validate_execution(repository, workflow_sha, run_id, run_attempt)

    manifest = fetch("MANIFEST.json", MANIFEST_SHA256)
    expected = canonical_files(manifest)
    current = read_update_receipt()
    if current is not None:
        receipt, raw = current
        if (
            receipt.get("result") == "HOST_UPDATE_OK"
            and receipt.get("source_commit") == RULES_COMMIT
            and receipt.get("rules_version") == RULES_VERSION
        ):
            evidence = verify_update_receipt(receipt, expected)
            bound = write_run_receipt(
                outcome="NOTERI_GATEWAY_ALREADY_CURRENT_VERIFIED",
                installation_performed=False,
                source_receipt=receipt,
                source_raw=raw,
                evidence=evidence,
                repository=repository,
                workflow_sha=workflow_sha,
                run_id=run_id,
                run_attempt=run_attempt,
            )
            return {"ok": True, "result": bound["result"]}

    if (not isinstance(legacy_receipt_sha256, str)
            or not SHA256_RE.fullmatch(legacy_receipt_sha256)
            or not isinstance(legacy_manifest_sha256, str)
            or not SHA256_RE.fullmatch(legacy_manifest_sha256)):
        raise RefreshError("pins legados obrigatorios para update")

    install = fetch("scripts/install_command_gateway_host.py", INSTALL_SHA256)
    update = fetch("scripts/update_command_gateway_host.py", UPDATE_SHA256)
    legacy_verify = fetch(
        "scripts/noteri_gateway_legacy_v1_rebaseline.py", LEGACY_VERIFY_SHA256
    )
    old_raw = current[1] if current is not None else None
    started_at = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="noteri-gateway-refresh-") as temp:
        root = Path(temp)
        (root / "install_command_gateway_host.py").write_bytes(install)
        (root / "noteri_gateway_legacy_v1_rebaseline.py").write_bytes(legacy_verify)
        updater = root / "update_command_gateway_host.py"
        updater.write_bytes(update)
        result = subprocess.run(
            [sys.executable, str(updater), "--commit", RULES_COMMIT,
             "--expected-self-sha256", UPDATE_SHA256, "--install-root",
             str(INSTALL_ROOT), "--work-root", str(WORK_ROOT),
             "--noteri-legacy-v1-rebaseline",
             "--expected-legacy-receipt-sha256", legacy_receipt_sha256,
             "--expected-legacy-manifest-sha256", legacy_manifest_sha256,
             "--noteri-wsl-inventory-profile"],
            capture_output=True, text=True, timeout=180, check=False,
        )
        if result.returncode != 0:
            raise RefreshError(f"updater_failed:{result.returncode}")

    updated = read_update_receipt()
    if updated is None:
        raise RefreshError("recibo de update ausente")
    receipt, raw = updated
    if old_raw is not None and sha256(raw) == sha256(old_raw):
        raise RefreshError("recibo de update nao foi renovado")
    evidence = verify_update_receipt(receipt, expected)
    if evidence["updated_at"] < started_at:
        raise RefreshError("recibo de update antecede esta execucao")
    bound = write_run_receipt(
        outcome="NOTERI_GATEWAY_REFRESHED",
        installation_performed=True,
        source_receipt=receipt,
        source_raw=raw,
        evidence=evidence,
        repository=repository,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
    )
    return {"ok": True, "result": bound["result"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--commit", default=RULES_COMMIT)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--expected-legacy-receipt-sha256")
    parser.add_argument("--expected-legacy-manifest-sha256")
    args = parser.parse_args()
    try:
        output = run_elevated(
            args.confirm, args.commit, repository=args.workflow_repository,
            workflow_sha=args.workflow_sha, run_id=args.workflow_run_id,
            run_attempt=args.workflow_run_attempt,
            legacy_receipt_sha256=args.expected_legacy_receipt_sha256,
            legacy_manifest_sha256=args.expected_legacy_manifest_sha256,
        )
    except Exception as exc:
        output = {"ok": False, "result": "NOTERI_GATEWAY_REFRESH_BLOCKED",
                  "error_type": type(exc).__name__, "error": str(exc)[:1000]}
    print(json.dumps(output, sort_keys=True))
    return 0 if output.get("ok") else 3


if __name__ == "__main__":
    raise SystemExit(main())

