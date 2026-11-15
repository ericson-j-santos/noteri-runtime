#!/usr/bin/env python3
"""Sonda HTTP e titularidade da porta do Ollama existente no Noteri DEV.

GETs locais fixos, nenhum POST, downloads, encerramento ou reinício de serviço.
Requer sessão governada e Command Gateway Risk1 na versão Git fixa.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import json
import os
import re
import socket
import struct
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import noteri_control_plane_watchdog as watchdog
from noteri_ollama_recovery_preflight import source_sha

CONFIRM = "PROBE-NOTERI-OLLAMA-HTTP-OWNER-READONLY"
MODEL = "qwen2.5-coder:7b"
EXPECTED_DIGEST = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9._:-]{12,128}\Z")
MAX_JSON = 256 * 1024
PORT = 11434
IPV4_TCP_LISTEN = 2
IPV4_OWNER_TABLE_ALL = 5
MAX_TABLE = 1024 * 1024


class ProbeBlocked(ValueError):
    pass


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise ProbeBlocked("REDIRECT_DENIED")


def local_http_json(route: str) -> dict[str, Any]:
    if route not in ("/api/version", "/api/tags"):
        raise ProbeBlocked("ROUTE_NOT_ALLOWLISTED")
    req = urllib.request.Request(
        "http://127.0.0.1:11434" + route,
        headers={"Accept": "application/json"}, method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), RejectRedirect(),
    )
    result: dict[str, Any] = {"route": route, "result": "UNAVAILABLE",
                              "http_status": None, "response_bytes": 0}
    try:
        with opener.open(req, timeout=8) as response:
            result["http_status"] = response.status
            if response.status != 200:
                result["result"] = "HTTP_NOT_200"
                return result
            raw = response.read(MAX_JSON + 1)
            content_type = response.headers.get("Content-Type", "")
            result["content_type_json"] = "json" in content_type.lower()
            if not 0 < len(raw) <= MAX_JSON:
                result["result"] = "JSON_RESPONSE_SIZE_INVALID"
                return result
            data = json.loads(raw.decode("utf-8"))
            result["response_bytes"] = len(raw)
    except urllib.error.HTTPError as exc:
        result["result"] = "HTTP_ERROR"
        result["http_status"] = exc.code
        return result
    except ProbeBlocked as exc:
        result["result"] = str(exc)
        return result
    except (OSError, ValueError, UnicodeError, urllib.error.URLError) as exc:
        result["result"] = "TRANSPORT_OR_JSON_FAILED"
        result["error_type"] = type(exc).__name__
        return result
    if type(data) is not dict:
        result["result"] = "SCHEMA_INVALID"
        return result
    if route == "/api/version":
        version = data.get("version")
        if type(version) is str and re.fullmatch(r"[0-9A-Za-z.+_\-]{1,40}", version):
            result["result"] = "VERSION_OK"
            result["version"] = version
        else:
            result["result"] = "VERSION_INVALID"
        return result
    models = data.get("models")
    if type(models) is not list or len(models) > 300:
        result["result"] = "MODEL_LIST_INVALID"
        return result
    result["model_count"] = len(models)
    matching = [x for x in models if type(x) is dict
                and (x.get("name") == MODEL or x.get("model") == MODEL)]
    if len(matching) != 1 or type(matching[0].get("digest")) is not str:
        result["result"] = "TARGET_MODEL_NOT_UNIQUELY_FOUND"
        return result
    observed = matching[0]["digest"].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", observed):
        result["result"] = "TARGET_DIGEST_MALFORMED"
        return result
    result["target_digest"] = observed
    result["official_digest_match"] = observed == EXPECTED_DIGEST
    result["result"] = ("MODEL_DIGEST_OK" if result["official_digest_match"]
                        else "TARGET_DIGEST_MISMATCH")
    return result


def listener_pids() -> list[int]:
    if os.name != "nt":
        raise ProbeBlocked("NOT_WINDOWS")
    try:
        method = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
        method.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool,
            ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
        ]
        method.restype = ctypes.c_ulong
        size = ctypes.c_ulong(0)
        if method(None, ctypes.byref(size), False, 2, IPV4_OWNER_TABLE_ALL, 0) != 122:
            raise ProbeBlocked("TCP_TABLE_SIZE_UNAVAILABLE")
        if not 4 <= size.value <= MAX_TABLE:
            raise ProbeBlocked("TCP_TABLE_SIZE_INVALID")
        buf = ctypes.create_string_buffer(size.value)
        if method(buf, ctypes.byref(size), False, 2, IPV4_OWNER_TABLE_ALL, 0) != 0:
            raise ProbeBlocked("TCP_TABLE_UNAVAILABLE")
        raw = buf.raw[:size.value]
        count = struct.unpack_from("<I", raw, 0)[0]
        if count > (MAX_TABLE - 4) // 24 or 4 + count * 24 > len(raw):
            raise ProbeBlocked("TCP_TABLE_INVALID")
        result = []
        for i in range(count):
            state, _la, port, _ra, _rp, pid = struct.unpack_from(
                "<6I", raw, 4 + i * 24)
            if state == IPV4_TCP_LISTEN and socket.ntohs(port & 0xffff) == PORT:
                if pid == 0:
                    raise ProbeBlocked("TCP_PID_UNAVAILABLE")
                result.append(pid)
        return sorted(set(result))
    except ProbeBlocked:
        raise
    except (OSError, ValueError, struct.error, AttributeError):
        raise ProbeBlocked("TCP_TABLE_PROBE_FAILED") from None


def identify_pids(pids: list[int]) -> list[dict[str, Any]]:
    if not pids:
        return []
    tasklist = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "tasklist.exe"
    if not tasklist.is_file():
        raise ProbeBlocked("TASKLIST_NOT_AVAILABLE")
    try:
        out = subprocess.run(
            [str(tasklist), "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=12,
            encoding="utf-8", errors="replace", check=False,
        )
        if out.returncode or len(out.stdout) > MAX_TABLE:
            raise ProbeBlocked("TASKLIST_FAILED")
        rows = list(csv.reader(out.stdout.splitlines()))
        proc = {int(row[1]): row[0].strip().casefold()
                for row in rows if len(row) >= 2 and row[1].strip().isdigit()}
    except (OSError, ValueError, csv.Error, subprocess.SubprocessError):
        raise ProbeBlocked("TASKLIST_FAILED") from None
    return [{"pid": pid, "name": proc.get(pid, "UNKNOWN")}
            for pid in pids]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        if (args.confirm != CONFIRM
                or SHA40.fullmatch(args.expected_sha) is None
                or CORRELATION.fullmatch(args.correlation_id) is None
                or socket.gethostname().casefold() != "noteri"
                or os.name != "nt"
                or watchdog.runtime_profile() != "NORMAL"
                or source_sha(Path(__file__).resolve().parents[1]) != args.expected_sha):
            raise ProbeBlocked("SOURCE_OR_HOST_NOT_ATTESTED")
        pids = listener_pids()
        owners = identify_pids(pids)
        version = local_http_json("/api/version")
        tags = local_http_json("/api/tags")
        output = {
            "result": "NOTERI_OLLAMA_HTTP_OWNER_READONLY",
            "host": "Noteri", "profile": "NORMAL",
            "listener_owners": owners,
            "listener_owner_is_ollama": (len(owners) == 1
                                         and owners[0]["name"] == "ollama.exe"),
            "version_api": version, "tags_api": tags,
            "model_ready": (len(owners) == 1 and owners[0]["name"] == "ollama.exe"
                            and version["result"] == "VERSION_OK"
                            and tags["result"] == "MODEL_DIGEST_OK"),
            "state_changed": False, "model_started": False,
            "model_downloaded": False,
            "source_sha": args.expected_sha, "correlation_id": args.correlation_id,
        }
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, ValueError, ProbeBlocked) as exc:
        print(json.dumps({"result": "NOTERI_OLLAMA_HTTP_OWNER_BLOCKED",
                          "reason": str(exc) if isinstance(exc, ProbeBlocked)
                          else "PROBE_FAILED",
                          "state_changed": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
