#!/usr/bin/env python3
"""Upgrade transacional do watchdog do Noteri (somente por Gateway autorizado).

Nao e um bootstrap nem um atalho de permissao: a API de mutacao exige caller
admin ja autorizado, SHA fixado, backup íntegro e readback independente.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-zA-Z0-9_-]{8,80}\Z")
CONFIRM = "UPGRADE-NOTERI-WATCHDOG-TRANSACTIONAL"
REPOSITORY = "ericson-j-santos/noteri-runtime"


class UpgradeBlocked(RuntimeError):
    pass


@dataclass(frozen=True)
class Request:
    old_sha: str
    old_digest: str
    target_sha: str
    target_digest: str
    correlation_id: str

    def validate(self) -> None:
        if not SHA.fullmatch(self.old_sha) or not SHA.fullmatch(self.target_sha):
            raise UpgradeBlocked("SHA_INVALID")
        if not DIGEST.fullmatch(self.old_digest) or not DIGEST.fullmatch(self.target_digest):
            raise UpgradeBlocked("DIGEST_INVALID")
        if not ID.fullmatch(self.correlation_id):
            raise UpgradeBlocked("CORRELATION_INVALID")
        if self.old_sha == self.target_sha:
            raise UpgradeBlocked("SAME_VERSION_USE_IDEMPOTENT_READBACK")


@dataclass(frozen=True)
class Snapshot:
    source_sha: str
    release_digest: str
    metadata: bytes
    task_xml: bytes
    installed_release: bytes


class Adapter(Protocol):
    def inspect(self) -> Snapshot: ...
    def verify_source(self, req: Request) -> None: ...
    def install(self, req: Request) -> None: ...
    def restore(self, saved: Snapshot) -> None: ...


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_exclusive(path: Path, value: bytes) -> None:
    with path.open("xb") as f:
        f.write(value)
        f.flush()
        os.fsync(f.fileno())
    if path.read_bytes() != value:
        raise UpgradeBlocked("BACKUP_READBACK_MISMATCH")


def _backup(root: Path, req: Request, state: Snapshot) -> Path:
    # O root nao vem do usuario: WindowsAdapter define o runtime root canônico.
    if root.is_symlink() or root.joinpath("backups").is_symlink():
        raise UpgradeBlocked("BACKUP_ROOT_REDIRECTED")
    backups = root / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    directory = backups / f"upgrade-{req.correlation_id}"
    directory.mkdir(mode=0o700, exist_ok=False)
    files = {"task.xml": state.task_xml, "metadata.json": state.metadata,
             "old-release.py": state.installed_release}
    for name, value in files.items():
        _write_exclusive(directory / name, value)
    manifest = {"schema_version": 1, "old_sha": req.old_sha,
                "target_sha": req.target_sha,
                "hashes": {name: _hash(value) for name, value in files.items()}}
    _write_exclusive(directory / "manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())
    for name, digest in manifest["hashes"].items():
        if _hash((directory / name).read_bytes()) != digest:
            raise UpgradeBlocked("BACKUP_DIGEST_MISMATCH")
    return directory


def _transact_core(adapter: Adapter, req: Request, backup_root: Path, *,
             authorized: bool = False, confirm: str = "") -> dict[str, object]:
    """Realiza upgrade somente se todas as precondicoes forem comprovadas.

    `authorized=False` e um preflight realmente sem mutacao (sem backup).
    `authorized=True` ainda precisa da confirmacao exata e do controle externo
    de sessao, Gateway, permissao, lock e autorizacao humana.
    """
    req.validate()
    adapter.verify_source(req)
    before = adapter.inspect()
    if before.source_sha == req.target_sha:
        if before.release_digest != req.target_digest:
            raise UpgradeBlocked("TARGET_DIGEST_MISMATCH")
        return {"result": "ALREADY_CURRENT", "state_changed": False, "target_sha": req.target_sha}
    if before.source_sha != req.old_sha or before.release_digest != req.old_digest:
        raise UpgradeBlocked("PREVIOUS_VERSION_MISMATCH")
    if _hash(before.installed_release) != req.old_digest:
        raise UpgradeBlocked("PREVIOUS_BYTES_MISMATCH")
    if not authorized:
        return {"result": "PREFLIGHT_OK_NOT_AUTHORIZED", "state_changed": False,
                "target_sha": req.target_sha, "old_sha": req.old_sha}
    if confirm != CONFIRM:
        raise UpgradeBlocked("EXPLICIT_CONFIRMATION_REQUIRED")
    directory = _backup(backup_root, req, before)
    try:
        adapter.install(req)
        after = adapter.inspect()  # leitura da tarefa e dos bytes reais, nao do exit-code
        if after.source_sha != req.target_sha or after.release_digest != req.target_digest:
            raise UpgradeBlocked("POST_INSTALL_ATTESTATION_MISMATCH")
        if _hash(after.installed_release) != req.target_digest:
            raise UpgradeBlocked("POST_INSTALL_BYTES_MISMATCH")
    except Exception as exc:
        try:
            adapter.restore(before)
            restored = adapter.inspect()
            if (restored.source_sha != before.source_sha or
                    restored.release_digest != before.release_digest or
                    restored.metadata != before.metadata or
                    _hash(restored.installed_release) != req.old_digest):
                raise UpgradeBlocked("ROLLBACK_READBACK_MISMATCH")
        except Exception as rollback_exc:
            raise UpgradeBlocked("ROLLBACK_FAILED_MANUAL_RECOVERY_REQUIRED;BACKUP_PRESERVED") from rollback_exc
        raise UpgradeBlocked("UPGRADE_FAILED_ROLLED_BACK;BACKUP_PRESERVED") from exc
    return {"result": "UPGRADE_VERIFIED", "state_changed": True,
            "target_sha": req.target_sha, "backup_manifest_sha256": _hash((directory / "manifest.json").read_bytes())}


@contextmanager
def _exclusive_upgrade_lease(root: Path):
    """Um unico escritor: queda inesperada preserva lock e bloqueia replay."""
    if root.is_symlink():
        raise UpgradeBlocked("LOCK_ROOT_REDIRECTED")
    lock = root / "upgrade.lock"
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("LOCKED_UPGRADE_REQUIRES_GOVERNED_SESSION\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # O lock permanece caso a escrita falhe, exige inspeção manual.
        raise
    try:
        yield
    except UpgradeBlocked as exc:
        if str(exc).startswith("ROLLBACK_FAILED_"):
            # Nao liberar a posse se a reversao deixou estado desconhecido.
            raise
        lock.unlink()
        raise
    except Exception:
        lock.unlink()
        raise
    else:
        lock.unlink()


def transact(adapter: Adapter, req: Request, backup_root: Path, *,
             authorized: bool = False, confirm: str = "") -> dict[str, object]:
    if not authorized:
        return _transact_core(adapter, req, backup_root, authorized=False, confirm=confirm)
    with _exclusive_upgrade_lease(backup_root):
        return _transact_core(adapter, req, backup_root, authorized=True, confirm=confirm)


def _task_contract(xml: bytes, release: Path, runner: Path) -> None:
    # Validar o Task Scheduler como fonte separada do metadata, antes da troca.
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise UpgradeBlocked("TASK_XML_INVALID") from exc
    action = root.findall("./t:Actions/t:Exec", ns)
    if len(action) != 1 or len(root.findall("./t:Actions/*", ns)) != 1:
        raise UpgradeBlocked("TASK_ACTION_UNEXPECTED")
    args = action[0].findtext("t:Arguments", default="", namespaces=ns)
    expected = subprocess.list2cmdline([str(release), "watch", "--runner-home", str(runner)])
    if args.casefold() != expected.casefold():
        raise UpgradeBlocked("TASK_ACTION_PATH_MISMATCH")
    if (root.findtext("./t:Principals/t:Principal/t:LogonType", namespaces=ns) or "").lower() != "s4u":
        raise UpgradeBlocked("TASK_LOGON_NOT_S4U")
    if root.find("./t:Triggers/t:BootTrigger", ns) is None:
        raise UpgradeBlocked("TASK_BOOT_TRIGGER_MISSING")
    if (root.findtext("./t:Settings/t:Enabled", default="true", namespaces=ns) or "true").lower() != "true":
        raise UpgradeBlocked("TASK_DISABLED")


class WindowsAdapter:
    def __init__(self, repo: Path) -> None:
        if os.name != "nt" or socket.gethostname().casefold() != "noteri":
            raise UpgradeBlocked("UNAUTHORIZED_HOST")
        # A sessao e o Gateway fornecem worktree exclusivo; nunca usar shell remoto.
        self.repo = repo.resolve(strict=True)
        if not self.repo.joinpath("scripts", "noteri_control_plane_watchdog.py").is_file():
            raise UpgradeBlocked("SOURCE_MISSING")
        import noteri_control_plane_watchdog as watchdog
        import noteri_control_plane_watchdog_uac_launcher as launcher
        self.watchdog, self.launcher = watchdog, launcher
        self.root = watchdog.runtime_root()
        self.metadata_path = watchdog.metadata_path()
        self.source = self.repo / "scripts" / "noteri_control_plane_watchdog.py"
        if self.launcher._path_is_redirect(self.source):
            raise UpgradeBlocked("SOURCE_REDIRECTED")

    def _task(self):
        service = self.watchdog._scheduler()
        return service.GetFolder(self.watchdog.TASK_FOLDER).GetTask(self.watchdog.TASK_LEAF_NAME)

    def inspect(self) -> Snapshot:
        raw = self.metadata_path.read_bytes()
        meta = json.loads(raw)
        old_sha = self.watchdog.validate_source_sha(meta["source_sha"])
        runner = self.watchdog.validate_runner_home(Path(meta["runner_home"]))
        self.launcher._guard_release_location(
            self.root, self.root / "releases" / old_sha / "scripts" / self.source.name)
        release = self.root / "releases" / old_sha / "scripts" / self.source.name
        expected = os.path.normcase(os.path.abspath(release))
        if os.path.normcase(os.path.abspath(meta["release_script"])) != expected:
            raise UpgradeBlocked("METADATA_RELEASE_PATH_MISMATCH")
        data = release.read_bytes()
        digest = _hash(data)
        if digest != meta["release_sha256"]:
            raise UpgradeBlocked("METADATA_DIGEST_MISMATCH")
        task_xml = self._task().Xml.encode("utf-8")
        _task_contract(task_xml, release, runner)
        return Snapshot(old_sha, digest, raw, task_xml, data)

    def verify_source(self, req: Request) -> None:
        observed = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True, timeout=20).stdout.strip()
        if observed != req.target_sha:
            raise UpgradeBlocked("WORKTREE_SHA_MISMATCH")
        origin = subprocess.run(["git", "-C", str(self.repo), "config", "--get", "remote.origin.url"],
                                capture_output=True, text=True, check=True, timeout=20).stdout.strip()
        if origin not in (f"https://github.com/{REPOSITORY}.git", f"https://github.com/{REPOSITORY}",
                          f"git@github.com:{REPOSITORY}.git"):
            raise UpgradeBlocked("REPOSITORY_ORIGIN_MISMATCH")
        if _hash(self.source.read_bytes()) != req.target_digest:
            raise UpgradeBlocked("TARGET_SOURCE_DIGEST_MISMATCH")
        cleanliness = subprocess.run(
            ["git", "-C", str(self.repo), "status", "--porcelain=v1", "--untracked-files=no"],
            capture_output=True, text=True, check=True, timeout=20).stdout.strip()
        if cleanliness:
            raise UpgradeBlocked("WORKTREE_TRACKED_CHANGES")

    def install(self, req: Request) -> None:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise UpgradeBlocked("ADMINISTRATIVE_APPROVAL_REQUIRED")
        meta = json.loads(self.metadata_path.read_bytes())
        result = self.watchdog.install(self.repo, Path(meta["runner_home"]), req.target_sha,
                                       self.watchdog.INSTALL_CONFIRM)
        if result.get("ok") is not True or result.get("headless_persistence") is not True:
            raise UpgradeBlocked("INSTALLER_DID_NOT_PROVE_HEADLESS")

    def restore(self, saved: Snapshot) -> None:
        # COM nativo preserva principal S4U e gatilho originalmente registrados.
        service = self.watchdog._scheduler()
        folder = service.GetFolder(self.watchdog.TASK_FOLDER)
        folder.RegisterTask(self.watchdog.TASK_LEAF_NAME, saved.task_xml.decode("utf-8"),
                            self.watchdog.TASK_CREATE_OR_UPDATE, None, None,
                            self.watchdog.TASK_LOGON_S4U)
        # Restaurar os bytes exatos de metadata, sem alterar/remover release antiga.
        current = self.metadata_path.read_bytes()
        if current != saved.metadata:
            tmp = self.metadata_path.with_name(self.metadata_path.name + ".rollback")
            _write_exclusive(tmp, saved.metadata)
            os.replace(tmp, self.metadata_path)
        _task_contract(self._task().Xml.encode("utf-8"),
                       self.root / "releases" / saved.source_sha / "scripts" / self.source.name,
                       Path(json.loads(saved.metadata)["runner_home"]))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo-root", type=Path, required=True)
    p.add_argument("--old-sha", required=True)
    p.add_argument("--old-digest", required=True)
    p.add_argument("--target-sha", required=True)
    p.add_argument("--target-digest", required=True)
    p.add_argument("--correlation-id", required=True)
    p.add_argument("--mode", choices=("preflight", "upgrade"), default="preflight")
    p.add_argument("--confirm", default="")
    args = p.parse_args()
    try:
        req = Request(args.old_sha, args.old_digest, args.target_sha, args.target_digest,
                      args.correlation_id)
        adapter = WindowsAdapter(args.repo_root)
        result = transact(adapter, req, adapter.root, authorized=args.mode == "upgrade",
                          confirm=args.confirm)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (UpgradeBlocked, OSError, ValueError, KeyError, RuntimeError) as exc:
        print(json.dumps({"result": "BLOCKED", "reason": str(exc)[:190],
                          "state_verified": False, "production_touched": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
