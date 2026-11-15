#!/usr/bin/env python3
"""Uma única inferência REAL do Qwen7B local, governada e de baixo impacto.

O fluxo é estrito: certificar modelo/porta/proprietário -> nenhuma inferência
em andamento -> POST pequeno na API loopback -> resposta real validada.
Nunca baixa modelo, instala, muda política, acessa cloud ou encerra processos.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import source_sha
from noteri_ollama_http_owner_probe import (
    EXPECTED_DIGEST, MODEL, RejectRedirect, identify_pids,
    listener_pids, local_http_json,
)

SCHEMA = 1
ACTION = "noteri.qwen7b.inference.once.dev.v1"
CONFIRM = "RUN-LOCAL-QWEN7B-ONE-INFERENCE-DEV"
IDEMPOTENCY = "noteri:qwen7b:smoke:20261115:once:v1"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
API = "http://127.0.0.1:11434/api"
MAX_BYTES = 128 * 1024
PROMPT = "Reply using exactly the single uppercase word READY, with no other text."


class ProbeBlocked(ValueError):
    pass


def request_json(path: str, payload: dict[str, Any] | None, timeout: int) -> dict[str, Any]:
    if path not in ("/ps", "/generate"):
        raise ProbeBlocked("ENDPOINT_NOT_ALLOWED")
    if (path == "/ps") != (payload is None):
        raise ProbeBlocked("REQUEST_METHOD_NOT_ALLOWED")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), RejectRedirect(),
    )
    request = urllib.request.Request(
        API + path,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="GET" if payload is None else "POST",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ProbeBlocked("LOCAL_API_HTTP_NOT_200")
            raw = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ProbeBlocked("LOCAL_API_HTTP_" + str(exc.code)) from None
    except (OSError, UnicodeError, ValueError, urllib.error.URLError):
        raise ProbeBlocked("LOCAL_API_UNAVAILABLE") from None
    if not 0 < len(raw) <= MAX_BYTES:
        raise ProbeBlocked("LOCAL_API_RESPONSE_SIZE")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise ProbeBlocked("LOCAL_API_JSON_INVALID") from None
    if type(result) is not dict:
        raise ProbeBlocked("LOCAL_API_SCHEMA_INVALID")
    return result


def infer_once() -> dict[str, Any]:
    owners = identify_pids(listener_pids())
    if not (len(owners) == 1 and owners[0]["name"] == "ollama.exe"):
        raise ProbeBlocked("OLLAMA_PORT_OWNER_NOT_UNIQUE")
    version = local_http_json("/api/version")
    tags = local_http_json("/api/tags")
    if (version.get("result") != "VERSION_OK"
            or tags.get("result") != "MODEL_DIGEST_OK"
            or tags.get("target_digest") != EXPECTED_DIGEST):
        raise ProbeBlocked("QWEN7B_NOT_INDEPENDENTLY_ATTESTED")
    loaded = request_json("/ps", None, timeout=8)
    active = loaded.get("models")
    if type(active) is not list:
        raise ProbeBlocked("ACTIVE_MODEL_STATUS_UNKNOWN")
    # Do not unload a model used by another task or evict a workload.
    if active:
        raise ProbeBlocked("ANOTHER_MODEL_ALREADY_LOADED")
    request = {
        "model": MODEL,
        "prompt": PROMPT,
        "stream": False,
        "keep_alive": 0,
        "options": {"num_predict": 12, "num_ctx": 512, "temperature": 0},
    }
    result = request_json("/generate", request, timeout=120)
    response = result.get("response")
    if (result.get("model") != MODEL or result.get("done") is not True
            or type(response) is not str or not response.strip()
            or len(response) > 512 or type(result.get("eval_count")) is not int
            or result["eval_count"] < 1):
        raise ProbeBlocked("INFERENCE_RESPONSE_NOT_PROVED")
    return {
        "result": "QWEN7B_LOCAL_INFERENCE_PROVED",
        "model": MODEL,
        "model_digest": EXPECTED_DIGEST,
        "ollama_version": version["version"],
        "prompt_fixed": True, "output_chars": len(response),
        "output_sha256": hashlib.sha256(response.encode("utf-8")).hexdigest(),
        "responded_exactly_ready": response.strip() == "READY",
        "tokens_generated": result["eval_count"],
        "done": True, "serving_pid": owners[0]["pid"],
        "model_downloaded": False, "model_installed": False,
        "process_started": False, "state_changed_persistently": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema-version", type=int, required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--confirm", required=True)
    a = parser.parse_args()
    try:
        if (a.schema_version != SCHEMA or a.action != ACTION
                or a.confirm != CONFIRM or a.idempotency_key != IDEMPOTENCY
                or not SHA40.fullmatch(a.expected_sha)
                or not CORRELATION.fullmatch(a.correlation_id)
                or socket.gethostname().casefold() != "noteri"
                or os.name != "nt" or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != a.expected_sha):
            raise ProbeBlocked("REQUEST_OR_SOURCE_NOT_AUTHORIZED")
        result = infer_once()
        result.update(source_sha=a.expected_sha, correlation_id=a.correlation_id)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProbeBlocked, OSError, ValueError) as exc:
        print(json.dumps({
            "result": "QWEN7B_LOCAL_INFERENCE_BLOCKED",
            "reason": str(exc) if isinstance(exc, ProbeBlocked) else "PROBE_UNAVAILABLE",
            "model_attested": False, "process_started": False,
            "model_downloaded": False, "state_changed_persistently": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
