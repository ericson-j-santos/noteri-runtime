#!/usr/bin/env python3
"""Fixed Task Scheduler entry point for the pinned Noteri Worker Pool API."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import sys
from pathlib import Path

import noteri_worker_pool_native_stage as stage

SOURCE_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(*, root: Path, executable: Path, hostname: str, platform: str) -> tuple[Path, Path]:
    if platform != "nt" or hostname.casefold() != "noteri":
        raise RuntimeError("blocked_host")
    localappdata = root.parents[1]
    profile = json.loads((localappdata / "ReqSys" / "TodoGlobal24x7" /
                          "host-profile.json").read_text(encoding="utf-8"))
    if profile.get("profile") != "NORMAL":
        raise RuntimeError("blocked_profile")
    release = root / "releases" / SOURCE_SHA
    venv_root = root / "venvs" / SOURCE_SHA
    token = root / "credentials" / "api-token.txt"
    for path in (release, venv_root, token):
        stage.ensure_no_link_components(path)
    manifest_path = release / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("source_sha") != SOURCE_SHA
            or manifest.get("source_repo") != stage.EXPECTED_REPO
            or manifest.get("kind") != "noteri_worker_pool_stage_only"
            or manifest.get("activated") is not False
            or not stage.validate_staged(release, manifest)):
        raise RuntimeError("blocked_release")
    venv_manifest = json.loads((venv_root / "noteri-venv-manifest.json").read_text(
        encoding="utf-8"))
    if (venv_manifest.get("source_sha") != SOURCE_SHA
            or venv_manifest.get("requirements_sha256") != manifest["files"]["requirements.txt"]
            or venv_manifest.get("python_sha256") != sha256(executable)
            or executable.resolve() != (venv_root / "Scripts" / "python.exe").resolve()):
        raise RuntimeError("blocked_venv")
    secure_path = release / "app" / "secure_file.py"
    spec = importlib.util.spec_from_file_location("noteri_staged_secure_file", secure_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("blocked_token_reference")
    secure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(secure)
    fd = secure.open_private_read(token)
    try:
        secure.validate_private_fd(fd)
        if not secure.path_matches_fd(fd, token, private=True):
            raise RuntimeError("blocked_token_reference")
    finally:
        os.close(fd)
    return release, token


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        release, token = validate(root=root, executable=Path(sys.executable),
                                  hostname=socket.gethostname(), platform=os.name)
    except Exception:
        print(json.dumps({"result": "BLOCKED_API_RUNNER"}))
        return 2
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    os.environ["CODEX_WORKER_POOL_DB"] = str(data / "pool.db")
    os.environ["CODEX_WORKER_POOL_BACKEND"] = "sqlite"
    os.environ["CODEX_WORKER_POOL_API_TOKEN_FILE"] = str(token)
    os.environ["CODEX_WORKER_POOL_EXPECTED_RULES_SHA"] = RULES_SHA
    os.environ.pop("CODEX_WORKER_POOL_FENCED_CUTOVER_ATTESTED", None)
    sys.path.insert(0, str(release))
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8097,
                access_log=False, log_config=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
