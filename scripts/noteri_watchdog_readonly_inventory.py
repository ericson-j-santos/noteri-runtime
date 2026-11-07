#!/usr/bin/env python3
"""Inventário sem mutação do watchdog persistente e do Qwen já instalado no Noteri.

Apenas capacidade Risk1: não instala, não escreve, não executa inferência,
não altera o perfil e não reserva runner. Sessão/Gateway externos obrigatórios.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog
import noteri_control_plane_watchdog_uac_launcher as launcher

CONFIRM = "INVENTORY-NOTERI-WATCHDOG-READONLY"
MODEL_NAME = "qwen2.5-coder:7b"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{12,128}$")
MAX_METADATA_BYTES = 32 * 1024
MAX_MODEL_RESPONSE_BYTES = 256 * 1024


class InventoryError(RuntimeError):
    pass


def require_identity(*, host: str, platform: str) -> None:
    if host.casefold() != "noteri" or platform != "nt":
        raise InventoryError("HOST_NOT_AUTHORIZED")


def checkout_sha(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
        text=True, check=False, timeout=6,
    )
    value = result.stdout.strip().lower()
    if result.returncode != 0 or not SHA_RE.fullmatch(value):
        raise InventoryError("SOURCE_SHA_UNAVAILABLE")
    return value


def safe_metadata(path: Path) -> dict[str, Any]:
    runtime = path.parent
    if launcher._path_is_redirect(runtime) or launcher._path_is_redirect(path):
        raise InventoryError("METADATA_REDIRECTED")
    if not path.is_file():
        raise InventoryError("METADATA_MISSING")
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise InventoryError("METADATA_TOO_LARGE")
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InventoryError("METADATA_INVALID") from exc
    if not isinstance(value, dict):
        raise InventoryError("METADATA_INVALID")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_model_tags() -> dict[str, Any]:
    """GET fixo somente no loopback; sem proxy, redirects, POST ou pull."""
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/tags",
        headers={"Accept": "application/json"}, method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
    )
    try:
        with opener.open(req, timeout=3) as response:
            if response.status != 200:
                return {"status": "UNAVAILABLE", "present": False, "digest": None}
            raw = response.read(MAX_MODEL_RESPONSE_BYTES + 1)
        if len(raw) > MAX_MODEL_RESPONSE_BYTES:
            return {"status": "INVALID_RESPONSE", "present": False, "digest": None}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, urllib.error.URLError):
        return {"status": "UNAVAILABLE", "present": False, "digest": None}
    if not isinstance(data, dict) or not isinstance(data.get("models"), list):
        return {"status": "INVALID_RESPONSE", "present": False, "digest": None}
    for item in data["models"]:
        if not isinstance(item, dict):
            continue
        if item.get("name") == MODEL_NAME or item.get("model") == MODEL_NAME:
            digest = item.get("digest")
            if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest.lower()):
                return {"status": "INVALID_DIGEST", "present": False, "digest": None}
            return {"status": "PRESENT", "present": True, "digest": digest.lower()}
    return {"status": "ABSENT", "present": False, "digest": None}



def task_action_attested(metadata: dict[str, Any], task: dict[str, Any]) -> bool:
    """Confronta a acao S4U efetiva com o release/runner versionados, sem divulgar caminhos."""
    if not isinstance(metadata, dict) or not isinstance(task, dict):
        return False
    if (task.get("action_count") != 1
            or task.get("action_python_observed") is not True):
        return False
    release = metadata.get("release_script")
    runner = metadata.get("runner_home")
    if (not isinstance(release, str) or not isinstance(runner, str)
            or not release or not runner or not Path(release).is_absolute()
            or not Path(runner).is_absolute()):
        return False
    expected_args = subprocess.list2cmdline(
        [release, "watch", "--runner-home", runner]
    )
    expected_hash = hashlib.sha256(expected_args.encode("utf-8")).hexdigest()
    return task.get("action_arguments_sha256") == expected_hash


def inventory(expected_sha: str, correlation_id: str, confirm: str) -> dict[str, Any]:
    if confirm != CONFIRM:
        raise InventoryError("CONFIRMATION_INVALID")
    if not SHA_RE.fullmatch(expected_sha):
        raise InventoryError("EXPECTED_SHA_INVALID")
    if not CORRELATION_RE.fullmatch(correlation_id):
        raise InventoryError("CORRELATION_ID_INVALID")
    require_identity(host=socket.gethostname(), platform=os.name)
    root = Path(__file__).resolve().parents[1]
    if checkout_sha(root) != expected_sha:
        raise InventoryError("SOURCE_SHA_MISMATCH")

    # Não chamar watchdog.cycle(), launcher.launch() ou instalador.
    profile = watchdog.runtime_profile()
    reasons: list[str] = []
    try:
        metadata = safe_metadata(watchdog.metadata_path())
    except InventoryError as exc:
        metadata = {}
        reasons.append(str(exc))
    source = root / "scripts" / "noteri_control_plane_watchdog.py"
    stored_sha = metadata.get("source_sha")
    if not isinstance(stored_sha, str) or not SHA_RE.fullmatch(stored_sha):
        stored_sha = None
    installed = False
    if metadata:
        try:
            launcher.attest_installed_release(metadata, expected_sha, source)
            installed = True
        except (launcher.LauncherError, OSError, ValueError, AttributeError, TypeError, KeyError) as exc:
            code = str(exc) if isinstance(exc, launcher.LauncherError) else ""
            reasons.append(code if code.startswith("WATCHDOG_INSTALLED_") else "WATCHDOG_ATTESTATION_FAILED")
    try:
        task = launcher.task_status()
        task_ready = isinstance(task, dict) and launcher.task_headless_ready(task)
        action_ready = task_ready and task_action_attested(metadata, task)
    except (OSError, ValueError, AttributeError, TypeError, KeyError):
        task_ready = False
        action_ready = False
    if not task_ready:
        reasons.append("TASK_S4U_NOT_VERIFIED")
    if not action_ready:
        reasons.append("TASK_ACTION_NOT_VERIFIED")
    if profile != "NORMAL":
        reasons.append("PROFILE_NOT_NORMAL")
    model = read_model_tags()
    if not model["present"]:
        reasons.append("QWEN7B_NOT_ATTESTED")
    return {
        "schema_version": 1,
        "result": "NOTERI_WATCHDOG_READONLY_INVENTORY",
        "correlation_id": correlation_id,
        "expected_sha": expected_sha,
        "installed_source_sha": stored_sha,
        "installed_attested": installed,
        "live_task_s4u": task_ready,
        "live_task_action_attested": action_ready,
        "profile": profile,
        "model_name": MODEL_NAME,
        "model": model,
        "blocking_reasons": sorted(set(reasons)),
        "source_sha_verified": True,
        "installation_authorized": False,
        "ready_for_builder": False,
        "session_gateway_readback_required": True,
        "task_action_readback_required": True,
        "cost_zero_attestation_required": True,
        "production_touched": False,
        "state_changed": False,
        "inference_performed": False,
        "model_downloaded": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        receipt = inventory(args.expected_sha, args.correlation_id, args.confirm)
    except (InventoryError, OSError, subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, InventoryError) else "INVENTORY_UNAVAILABLE"
        receipt = {
            "schema_version": 1, "result": "NOTERI_WATCHDOG_INVENTORY_BLOCKED",
            "reason": code, "state_changed": False, "production_touched": False,
            "ready_for_builder": False,
        }
        print(json.dumps(receipt, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
