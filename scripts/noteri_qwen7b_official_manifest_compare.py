#!/usr/bin/env python3
"""Compare manifests Qwen2.5-Coder 7B via HTTPS fixo, sem alterar modelo.

Busca APENAS o JSON pequeno e público do manifesto OCI no registro oficial.
Não lê conteúdo sensível, não baixa pesos, não modifica o disco e nunca inicia
Ollama. Executar após Session Launcher + Command Gateway Risk1, Noteri DEV.
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
from noteri_ollama_recovery_preflight import path_safe, source_sha

URL = "https://registry.ollama.ai/v2/library/qwen2.5-coder/manifests/7b"
EXPECTED_PREFIX = "dae161e27b0e"
EXPECTED_LOCAL_SHA = "4aaba1ee422af93aad53ecbdfc8a159770cf254a9950b7a4304cf9ee3555ef31"
CONFIRM = "COMPARE-NOTERI-QWEN7B-OFFICIAL-MANIFEST-READONLY"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
BLOB = re.compile(r"sha256:([0-9a-f]{64})\Z")


class CompareBlocked(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise CompareBlocked("OFFICIAL_REDIRECT_NOT_ALLOWED")


def fetch_official_manifest() -> bytes:
    """Manifest bytes only; no blob URLs, proxies, redirects or auth."""
    request = urllib.request.Request(
        URL,
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=12) as response:
            if response.status != 200:
                raise CompareBlocked("OFFICIAL_HTTP_NOT_200")
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
            if content_type not in (
                "application/vnd.docker.distribution.manifest.v2+json",
                "application/json",
                "application/vnd.oci.image.manifest.v1+json",
            ):
                raise CompareBlocked("OFFICIAL_CONTENT_TYPE")
            data = response.read(MAX_MANIFEST_BYTES + 1)
            header = response.headers.get("Docker-Content-Digest", "").strip().lower()
    except (OSError, urllib.error.URLError, TimeoutError):
        raise CompareBlocked("OFFICIAL_REGISTRY_UNAVAILABLE") from None

    if not 0 < len(data) <= MAX_MANIFEST_BYTES:
        raise CompareBlocked("OFFICIAL_BODY_INVALID")
    digest = hashlib.sha256(data).hexdigest()
    if not digest.startswith(EXPECTED_PREFIX):
        raise CompareBlocked("OFFICIAL_DIGEST_NOT_PINNED")
    if header and header != "sha256:" + digest:
        raise CompareBlocked("OFFICIAL_DIGEST_HEADER_MISMATCH")
    return data


def parse_descriptors(raw: bytes) -> tuple[dict[str, Any], list[tuple[str, int]]]:
    if not 0 < len(raw) <= MAX_MANIFEST_BYTES:
        raise CompareBlocked("MANIFEST_SIZE")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, TypeError):
        raise CompareBlocked("MANIFEST_JSON_INVALID") from None
    if type(obj) is not dict or type(obj.get("layers")) is not list:
        raise CompareBlocked("MANIFEST_SHAPE_INVALID")
    values = [obj.get("config"), *obj["layers"]]
    if not 2 <= len(values) <= 64:
        raise CompareBlocked("MANIFEST_LAYER_COUNT")
    parsed: list[tuple[str, int]] = []
    seen: set[str] = set()
    total = 0
    for item in values:
        if type(item) is not dict:
            raise CompareBlocked("MANIFEST_DESCRIPTOR_INVALID")
        digest, size = item.get("digest"), item.get("size")
        if (type(digest) is not str or BLOB.fullmatch(digest) is None
                or type(size) is not int or size < 0):
            raise CompareBlocked("MANIFEST_DESCRIPTOR_INVALID")
        if digest in seen:
            raise CompareBlocked("MANIFEST_DUPLICATE_DIGEST")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise CompareBlocked("MANIFEST_TOO_LARGE")
        seen.add(digest)
        parsed.append((digest, size))
    return obj, parsed


def compare(local: bytes, official: bytes, store: Path) -> dict[str, Any]:
    """Compare semantic JSON + all blob references, never claim readiness."""
    local_obj, local_refs = parse_descriptors(local)
    official_obj, official_refs = parse_descriptors(official)
    manifest_hash = hashlib.sha256(local).hexdigest()
    official_hash = hashlib.sha256(official).hexdigest()
    official_blob_set = set(official_refs)
    local_blob_set = set(local_refs)
    reusable = 0
    reusable_bytes = 0
    missing_bytes = 0
    missing_count = 0
    for digest, size in official_refs:
        blob = store / "blobs" / digest.replace(":", "-")
        if not path_safe(blob, store):
            raise CompareBlocked("BLOB_PATH_UNSAFE")
        try:
            usable = (blob.is_file() and not blob.is_symlink()
                      and blob.stat().st_size == size)
        except OSError:
            usable = False
        if usable:
            reusable += 1
            reusable_bytes += size
        else:
            missing_count += 1
            missing_bytes += size
    raw_equal = local == official
    json_equal = local_obj == official_obj
    references_equal = local_refs == official_refs
    if raw_equal:
        classification = "ALREADY_OFFICIAL"
    elif json_equal:
        classification = "SAME_JSON_DIFFERENT_ENCODING"
    elif references_equal:
        classification = "SAME_BLOBS_DIFFERENT_METADATA"
    elif missing_count == 0:
        classification = "OFFICIAL_BLOBS_PRESENT_METADATA_OR_REFERENCES_DIFFER"
    else:
        classification = "OFFICIAL_BLOBS_MISSING_DO_NOT_REPLACE"
    return {
        "result": "QWEN7B_MANIFEST_COMPARISON_READONLY",
        "classification": classification,
        "local_manifest_sha256": manifest_hash,
        "official_manifest_sha256": official_hash,
        "official_digest_pinned": official_hash.startswith(EXPECTED_PREFIX),
        "local_equals_expected_preflight": manifest_hash == EXPECTED_LOCAL_SHA,
        "manifest_bytes_equal": raw_equal,
        "manifest_json_equal": json_equal,
        "manifest_descriptors_equal": references_equal,
        "local_blob_references": len(local_blob_set),
        "official_blob_references": len(official_blob_set),
        "common_blob_references": len(local_blob_set & official_blob_set),
        "official_blobs_size_present": reusable,
        "official_blobs_size_missing": missing_count,
        "official_blob_bytes_size_present": reusable_bytes,
        "official_blob_bytes_missing": missing_bytes,
        "verified_official_blobs_by_hash": 0,
        "model_ready": False, "manifest_replaced": False,
        "model_downloaded": False, "state_changed": False,
        "repair_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        if (args.confirm != CONFIRM
                or not HEX40.fullmatch(args.expected_sha)
                or not CORRELATION.fullmatch(args.correlation_id)
                or socket.gethostname().casefold() != "noteri"
                or os.name != "nt"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(root) != args.expected_sha):
            raise CompareBlocked("SOURCE_OR_HOST_INVALID")
        home = Path.home()
        models = home / ".ollama" / "models"
        configured = os.environ.get("OLLAMA_MODELS", "")
        if configured and Path(configured) != models:
            raise CompareBlocked("CUSTOM_STORE_UNVERIFIED")
        manifest = models / "manifests" / "registry.ollama.ai" / "library" / "qwen2.5-coder" / "7b"
        if (not path_safe(manifest, home) or not manifest.is_file()
                or not 0 < manifest.stat().st_size <= MAX_MANIFEST_BYTES):
            raise CompareBlocked("LOCAL_MANIFEST_UNAVAILABLE")
        local = manifest.read_bytes()
        if hashlib.sha256(local).hexdigest() != EXPECTED_LOCAL_SHA:
            raise CompareBlocked("LOCAL_MANIFEST_DRIFT")
        official = fetch_official_manifest()
        result = compare(local, official, models)
        result.update(
            correlation_id=args.correlation_id, source_sha=args.expected_sha,
            registry="registry.ollama.ai", model="qwen2.5-coder:7b",
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CompareBlocked, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, CompareBlocked) else "LOCAL_CHECK_UNAVAILABLE"
        print(json.dumps({
            "result": "QWEN7B_MANIFEST_COMPARISON_BLOCKED",
            "reason": code, "model_ready": False,
            "manifest_replaced": False, "model_downloaded": False,
            "state_changed": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
