#!/usr/bin/env python3
"""Risk1 Noteri #42: observe Worker Pool health, never activate or claim."""
from __future__ import annotations
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

URL = "http://127.0.0.1:8097/health"
REPOSITORY = "ericson-j-santos/noteri-runtime"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")


class Blocked(RuntimeError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Blocked(code)


def authorize(env: dict[str, str], host: str, platform: str) -> None:
    need(
        platform == "nt" and host.casefold() == "noteri"
        and env.get("GITHUB_ACTIONS") == "true"
        and env.get("GITHUB_REPOSITORY") == REPOSITORY
        and env.get("RUNNER_NAME") == "Noteri-runtime"
        and SHA40.fullmatch(env.get("GITHUB_SHA", "")) is not None
        and env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
        and env.get("SESSION_STATE_VALIDATED") == "true"
        and env.get("SESSION_GATEWAY_BOUND") == "true"
        and SHA64.fullmatch(env.get("SESSION_SNAPSHOT_SHA256", "")) is not None,
        "NOTERI_POOL_CONTEXT_UNATTESTED",
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def read_health(opener=None) -> tuple[int, dict]:
    client = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    )
    request = urllib.request.Request(URL, method="GET")
    try:
        response = client.open(request, timeout=3)
    except urllib.error.HTTPError as exc:
        if exc.code != 503 or exc.geturl() != URL:
            raise Blocked("NOTERI_POOL_HEALTH_UNAVAILABLE") from None
        response = exc
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        raise Blocked("NOTERI_POOL_HEALTH_UNAVAILABLE") from None
    try:
        with response:
            need(response.geturl() == URL and response.status in (200, 503),
                 "NOTERI_POOL_HEALTH_RESPONSE_UNTRUSTED")
            raw = response.read(8193)
    except (OSError, ValueError):
        raise Blocked("NOTERI_POOL_HEALTH_READ_FAILED") from None
    need(0 < len(raw) <= 8192, "NOTERI_POOL_HEALTH_SIZE_INVALID")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Blocked("NOTERI_POOL_HEALTH_JSON_INVALID") from None
    need(type(value) is dict, "NOTERI_POOL_HEALTH_BODY_INVALID")
    return response.status, value


def staged_releases(localappdata: str | None) -> list[str]:
    need(type(localappdata) is str and bool(localappdata),
         "NOTERI_POOL_LOCALAPPDATA_MISSING")
    base = Path(localappdata)
    need(base.is_absolute() and not base.is_symlink(),
         "NOTERI_POOL_LOCALAPPDATA_UNTRUSTED")
    root = base / "ReqSys" / "NoteriWorkerPool" / "releases"
    if not root.exists():
        return []
    need(root.is_dir() and not root.is_symlink(),
         "NOTERI_POOL_RELEASE_ROOT_INVALID")
    try:
        entries = list(root.iterdir())
    except OSError:
        raise Blocked("NOTERI_POOL_RELEASE_IO_BLOCKED") from None
    need(len(entries) <= 64 and all(
        p.is_dir() and not p.is_symlink()
        and SHA40.fullmatch(p.name) is not None for p in entries
    ), "NOTERI_POOL_RELEASE_ENTRIES_INVALID")
    return sorted(p.name for p in entries)


def sanitize(status: int, body: dict, stages: list[str]) -> dict:
    need(type(status) is int and status in (200, 503)
         and body.get("status") in ("healthy", "not_ready")
         and body.get("storage_backend") in ("sqlite", "postgres", "postgresql")
         and type(body.get("fenced_cutover_enabled")) is bool
         and type(body.get("auth_configured")) is bool,
         "NOTERI_POOL_HEALTH_SCHEMA_INVALID")
    authority = body.get("authority_id")
    need(authority is None or (type(authority) is str and
         re.fullmatch(r"[0-9a-fA-F-]{32,36}", authority) is not None),
         "NOTERI_POOL_AUTHORITY_ID_INVALID")
    need(type(stages) is list and len(stages) <= 64 and all(
        type(s) is str and SHA40.fullmatch(s) is not None for s in stages
    ), "NOTERI_POOL_STAGE_SCHEMA_INVALID")
    return {
        "schema_version": 1, "result": "NOTERI_POOL_RISK1_READONLY",
        "http_status": status, "service_status": body["status"],
        "storage_backend": body["storage_backend"],
        "authority_id": authority,
        "fenced_cutover_enabled": body["fenced_cutover_enabled"],
        "auth_configured": body["auth_configured"],
        "staged_releases_unverified": stages,
        "active_release_sha": None,
        "legacy_claimers_drained_verified": False,
        "lease_verified": False, "cas_verified": False,
        "ready_for_builder": False, "ready_for_pr": False,
        "cost_zero_attested": False, "state_changed": False,
        "secrets_read": False,
    }


def main() -> int:
    need(len(sys.argv) == 1 and sys.dont_write_bytecode,
         "NOTERI_POOL_ARGUMENTS_OR_BYTECODE_BLOCKED")
    authorize(dict(os.environ), socket.gethostname(), os.name)
    stages = staged_releases(os.environ.get("LOCALAPPDATA"))
    status, body = read_health()
    print(json.dumps(sanitize(status, body, stages), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Blocked as exc:
        print(json.dumps({
            "schema_version": 1, "result": "NOTERI_POOL_RISK1_BLOCKED",
            "reason_code": str(exc), "ready_for_builder": False,
            "state_changed": False, "secrets_read": False,
        }, sort_keys=True))
        raise SystemExit(2) from None
