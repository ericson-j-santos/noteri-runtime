#!/usr/bin/env python3
"""E2E real do agente local do Noteri: NORMAL -> ESTUDO -> NORMAL."""
from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_PORT = 8765


def agent_url(port: int) -> str:
    if not 1 <= port <= 65535:
        raise ValueError("port deve estar entre 1 e 65535")
    return f"http://127.0.0.1:{port}"


def request(
    path: str,
    *,
    port: int = DEFAULT_PORT,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        agent_url(port) + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=3) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise RuntimeError(f"resposta inválida do agente: {payload}")
    return payload


def set_and_verify(profile: str, correlation_id: str, *, port: int = DEFAULT_PORT) -> dict[str, Any]:
    changed = request(
        "/v1/profile",
        port=port,
        method="POST",
        body={"host": "Noteri", "profile": profile, "correlation_id": correlation_id},
    )
    observed = request("/v1/profile", port=port)
    expected_acceptance = profile == "NORMAL"
    if observed.get("profile") != profile:
        raise RuntimeError(f"readback divergente: esperado {profile}, obtido {observed.get('profile')}")
    if observed.get("accepts_new_development") is not expected_acceptance:
        raise RuntimeError("accepts_new_development divergente")
    return {"changed": changed, "observed": observed}


def negative_control(correlation_id: str, *, port: int = DEFAULT_PORT) -> dict[str, Any]:
    try:
        request(
            "/v1/profile",
            port=port,
            method="POST",
            body={"host": "__invalid_host__", "profile": "ESTUDO", "correlation_id": correlation_id},
        )
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode("utf-8"))
        if exc.code != 409 or payload.get("error") != "host_target_mismatch":
            raise RuntimeError(f"controle negativo inesperado: http={exc.code} payload={payload}") from exc
        observed = request("/v1/profile", port=port)
        if observed.get("profile") != "NORMAL":
            raise RuntimeError("controle negativo alterou estado")
        return {"http_status": exc.code, "error": payload.get("error"), "observed": observed}
    raise RuntimeError("controle negativo não foi rejeitado")


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E real NORMAL/ESTUDO do Noteri")
    parser.add_argument("--correlation-prefix", default="noteri-study-live")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    if socket.gethostname().casefold() != "noteri":
        print(json.dumps({"ok": False, "error": "E2E deve rodar no host Noteri"}, ensure_ascii=False))
        return 2
    try:
        agent_url(args.port)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2

    stamp = str(int(time.time()))
    prefix = f"{args.correlation_prefix}-{stamp}"
    evidence: dict[str, Any] = {
        "host": socket.gethostname(),
        "port": args.port,
        "initial": None,
        "study": None,
        "normal": None,
        "normal_repeat": None,
        "negative_control": None,
        "final_readback": None,
    }
    try:
        evidence["initial"] = request("/v1/profile", port=args.port)
        if evidence["initial"].get("profile") != "NORMAL":
            set_and_verify("NORMAL", prefix + "-pre-normal", port=args.port)
        evidence["study"] = set_and_verify("ESTUDO", prefix + "-estudo", port=args.port)
        evidence["normal"] = set_and_verify("NORMAL", prefix + "-normal", port=args.port)
        evidence["normal_repeat"] = set_and_verify("NORMAL", prefix + "-normal-repeat", port=args.port)
        if evidence["normal_repeat"]["changed"].get("changed") is not False:
            raise RuntimeError("replay idempotente alterou estado")
        evidence["negative_control"] = negative_control(prefix + "-negative", port=args.port)
        evidence["final_readback"] = request("/v1/profile", port=args.port)
        if evidence["final_readback"].get("profile") != "NORMAL":
            raise RuntimeError("estado final não permaneceu NORMAL")
        print(json.dumps({"ok": True, "result": "NOTERI_STUDY_E2E_OK", **evidence}, ensure_ascii=False, sort_keys=True))
        return 0
    except (OSError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), **evidence}, ensure_ascii=False, sort_keys=True))
        return 1
    finally:
        try:
            set_and_verify("NORMAL", prefix + "-finally-normal", port=args.port)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
