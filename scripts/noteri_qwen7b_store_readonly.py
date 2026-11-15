#!/usr/bin/env python3
"""Sonda restrita do manifesto Qwen7B local; sem executar Ollama ou ler segredos."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
from pathlib import Path

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import path_safe, source_sha

CONFIRM = "INSPECT-NOTERI-QWEN7B-LOCAL-MANIFEST-READONLY"
DIGEST_PREFIX = "dae161e27b0e"
SHA = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
BLOB_SHA = re.compile(r"sha256:([0-9a-f]{64})\Z")


def assess_model_store(home: Path, custom_location: bool) -> dict[str, object]:
    result: dict[str, object] = {
        "manifest": "UNKNOWN", "digest_prefix_match": False,
        "blobs_checked": 0, "blobs_missing_or_untrusted": 0,
        "model_ready": False,
    }
    if custom_location:
        result["manifest"] = "CUSTOM_STORE_UNVERIFIED"
        return result
    store = home / ".ollama" / "models"
    manifest = (store / "manifests" / "registry.ollama.ai"
                / "library" / "qwen2.5-coder" / "7b")
    if not path_safe(manifest, home):
        result["manifest"] = "UNSAFE_PATH"
        return result
    try:
        if not manifest.exists():
            result["manifest"] = "MISSING_DEFAULT_STORE"
            return result
        if not manifest.is_file() or manifest.stat().st_size > 131072:
            result["manifest"] = "INVALID_MANIFEST"
            return result
        payload = manifest.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        result["digest_prefix_match"] = digest.startswith(DIGEST_PREFIX)
        obj = json.loads(payload.decode("utf-8"))
        if type(obj) is not dict or type(obj.get("layers")) is not list:
            result["manifest"] = "INVALID_MANIFEST"
            return result
        descriptors = [obj.get("config"), *obj["layers"]]
        if not 2 <= len(descriptors) <= 64 or not all(type(v) is dict for v in descriptors):
            result["manifest"] = "INVALID_MANIFEST"
            return result
        for item in descriptors:
            value = item.get("digest")
            size = item.get("size")
            match = BLOB_SHA.fullmatch(value) if type(value) is str else None
            if match is None or type(size) is not int or size < 0 or size > 100_000_000_000:
                result["manifest"] = "INVALID_MANIFEST"
                return result
            blob = store / "blobs" / ("sha256-" + match.group(1))
            if not path_safe(blob, home):
                result["manifest"] = "UNSAFE_PATH"
                return result
            result["blobs_checked"] = int(result["blobs_checked"]) + 1
            if (not blob.is_file() or blob.is_symlink()
                    or blob.stat().st_size != size):
                result["blobs_missing_or_untrusted"] = (
                    int(result["blobs_missing_or_untrusted"]) + 1
                )
        result["manifest"] = "PRESENT"
        result["model_ready"] = (
            result["digest_prefix_match"]
            and result["blobs_missing_or_untrusted"] == 0
        )
    except (OSError, ValueError, UnicodeError, TypeError):
        result["manifest"] = "UNAVAILABLE_OR_INVALID"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    a = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        if (a.confirm != CONFIRM or not SHA.fullmatch(a.expected_sha)
                or not CORRELATION.fullmatch(a.correlation_id)
                or socket.gethostname().casefold() != "noteri"
                or os.name != "nt" or watchdog.runtime_profile() != "NORMAL"
                or source_sha(root) != a.expected_sha):
            raise ValueError("IDENTITY_OR_SOURCE")
        home = Path.home()
        store_var = os.environ.get("OLLAMA_MODELS", "")
        canonical = home / ".ollama" / "models"
        custom = bool(store_var and Path(store_var) != canonical)
        report = assess_model_store(home, custom)
        report.update(
            result="NOTERI_QWEN7B_LOCAL_STORE_READONLY",
            correlation_id=a.correlation_id,
            source_sha=a.expected_sha,
            state_changed=False, model_started=False, model_downloaded=False,
        )
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError):
        print(json.dumps({
            "result": "NOTERI_QWEN7B_LOCAL_STORE_BLOCKED",
            "state_changed": False,
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
