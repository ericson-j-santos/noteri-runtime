#!/usr/bin/env python3
"""Verificar SHA-256 dos blobs Qwen7B locais sem rede, download ou execução do modelo."""
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

CONFIRM = "VERIFY-NOTERI-QWEN7B-BLOBS-SHA256-READONLY"
MODEL_NAME = "qwen2.5-coder:7b"
PIN = "dae161e27b0e"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
BLOB = re.compile(r"sha256:([0-9a-f]{64})\Z")
MAX_TOTAL = 8 * 1024 * 1024 * 1024
MAX_MANIFEST = 131072


def verify_store(home: Path, custom_store: bool = False) -> dict[str, object]:
    out: dict[str, object] = {
        "model_name": MODEL_NAME, "result": "BLOCKED_STORE_INTEGRITY",
        "manifest_sha256": None, "manifest_pin_match": False,
        "blob_count": 0, "bytes_hashed": 0, "blobs_sha256_verified": 0,
        "blobs_bad": 0, "model_ready": False, "state_changed": False,
    }
    if custom_store:
        out["reason"] = "CUSTOM_STORE_UNVERIFIED"
        return out
    store = home / ".ollama" / "models"
    manifest = (store / "manifests" / "registry.ollama.ai" / "library"
                / "qwen2.5-coder" / "7b")
    if not path_safe(manifest, home):
        out["reason"] = "UNSAFE_PATH"
        return out
    try:
        if not manifest.is_file() or not 0 < manifest.stat().st_size <= MAX_MANIFEST:
            out["reason"] = "MANIFEST_UNAVAILABLE"
            return out
        raw = manifest.read_bytes()
        manifest_sha = hashlib.sha256(raw).hexdigest()
        out["manifest_sha256"] = manifest_sha
        out["manifest_pin_match"] = manifest_sha.startswith(PIN)
        payload = json.loads(raw.decode("utf-8"))
        if type(payload) is not dict or type(payload.get("layers")) is not list:
            out["reason"] = "MANIFEST_INVALID"
            return out
        members = [payload.get("config"), *payload["layers"]]
        if not 2 <= len(members) <= 64 or any(type(v) is not dict for v in members):
            out["reason"] = "MANIFEST_INVALID"
            return out
        entries = []
        seen = set()
        total = 0
        for member in members:
            digest = member.get("digest")
            match = BLOB.fullmatch(digest) if type(digest) is str else None
            size = member.get("size")
            if match is None or type(size) is not int or not 0 <= size <= MAX_TOTAL:
                out["reason"] = "MANIFEST_INVALID"
                return out
            if digest in seen:
                out["reason"] = "DUPLICATE_BLOB"
                return out
            seen.add(digest)
            total += size
            if total > MAX_TOTAL:
                out["reason"] = "TOTAL_SIZE_LIMIT"
                return out
            entries.append((match.group(1), size))
        out["blob_count"] = len(entries)
        # Only verified byte-for-byte SHA-256 is counted as cryptographic proof.
        for digest, size in entries:
            blob = store / "blobs" / ("sha256-" + digest)
            if not path_safe(blob, home) or not blob.is_file() or blob.stat().st_size != size:
                out["blobs_bad"] = int(out["blobs_bad"]) + 1
                continue
            sha = hashlib.sha256()
            count = 0
            with blob.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    count += len(chunk)
                    sha.update(chunk)
            out["bytes_hashed"] = int(out["bytes_hashed"]) + count
            if count == size and sha.hexdigest() == digest:
                out["blobs_sha256_verified"] = int(out["blobs_sha256_verified"]) + 1
            else:
                out["blobs_bad"] = int(out["blobs_bad"]) + 1
        out["result"] = ("STORE_BLOBS_SHA256_VERIFIED" if
                         out["blobs_sha256_verified"] == out["blob_count"]
                         and out["blobs_bad"] == 0
                         else "BLOCKED_STORE_INTEGRITY")
    except (OSError, ValueError, UnicodeError, TypeError):
        out["result"] = "BLOCKED_STORE_INTEGRITY"
        out["reason"] = "STORE_READ_OR_PARSE_FAILED"
    # A file-integrity check never admits a model or changes the Builder pin.
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    a = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        if (a.confirm != CONFIRM or not SHA40.fullmatch(a.expected_sha)
                or not CORRELATION.fullmatch(a.correlation_id)
                or socket.gethostname().casefold() != "noteri"
                or os.name != "nt" or watchdog.runtime_profile() != "NORMAL"
                or source_sha(root) != a.expected_sha):
            raise ValueError("IDENTITY_NOT_PROVED")
        home = Path.home()
        configured = os.environ.get("OLLAMA_MODELS", "")
        custom = bool(configured and Path(configured) != home / ".ollama" / "models")
        report = verify_store(home, custom)
        report.update(correlation_id=a.correlation_id, source_sha=a.expected_sha)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["result"] == "STORE_BLOBS_SHA256_VERIFIED" else 2
    except (OSError, ValueError):
        print(json.dumps({
            "result": "BLOCKED_SOURCE_OR_HOST", "state_changed": False,
        }))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
