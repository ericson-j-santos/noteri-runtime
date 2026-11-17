#!/usr/bin/env python3
"""Ingestao privada e tipada do PBIX STORE, exclusiva do Noteri DEV.

Este modulo nao faz bootstrap, nao contorna Gateway, nao instala pacotes,
nao abre o Power BI e nao le dados do relatorio. Executar somente dentro de
sessao governada valida, sob Command Gateway, depois de deploy autorizado.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

SCHEMA = "1"
HOST = "Noteri"
SOURCE_ID_SHA256 = "b23a4874f84432854a54494f076d618ec802203f0f908d6063bb6566dd180bac"
FILE_NAME = "Aula_06_Dashboard_Financeiro_Final.pbix"
EXPECTED_BYTES = 5_317_713
EXPECTED_SHA256 = "6a2d4584718c2263444b78b43eb4381e4d6acc03a9645d9649d527fd228deb00"
CRED_TARGET = "ReqSys/PowerBIStore/DriveOAuthAccessToken"
CONFIRM = "INGEST-POWERBI-STORE-NOTERI-DEV"
CORRELATION = "powerbi-store-20261116-r2"
IDEMPOTENCY = "powerbi-store-noteri-20261116-v1"
SOURCE_CONFIG = Path(r"C:\ProgramData\ReqSys\PowerBIStore\source-file-id.txt")

class Blocked(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def guard(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)


def _no_reparse(path: Path) -> None:
    """Falha em links/reparse points em qualquer ancestral existente."""
    for node in (path, *path.parents):
        try:
            st = node.lstat()
        except FileNotFoundError:
            continue
        guard(not stat.S_ISLNK(st.st_mode), "REPARSE_PATH_REJECTED")
        guard(not (getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                   if hasattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT") else 0),
              "REPARSE_PATH_REJECTED")


def _sha_of_file(path: Path) -> tuple[int, str]:
    _no_reparse(path)
    guard(path.is_file(), "TARGET_NOT_REGULAR")
    size = 0
    h = hashlib.sha256()
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as inp:
            before = os.fstat(inp.fileno())
            guard(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "TARGET_NOT_REGULAR")
            guard(before.st_size <= EXPECTED_BYTES, "TARGET_SIZE_MISMATCH")
            for chunk in iter(lambda: inp.read(1024 * 1024), b""):
                size += len(chunk)
                guard(size <= EXPECTED_BYTES, "TARGET_SIZE_MISMATCH")
                h.update(chunk)
            after = os.fstat(inp.fileno())
            guard((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                  (before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                  "TARGET_CHANGED_DURING_READ")
    except OSError:
        raise Blocked("TARGET_READ_FAILED") from None
    return size, h.hexdigest()


def _check_existing(target: Path) -> bool:
    _no_reparse(target)
    if not target.exists() and not target.is_symlink():
        return False
    size, digest = _sha_of_file(target)
    guard(size == EXPECTED_BYTES and digest == EXPECTED_SHA256, "TARGET_CONTENT_CONFLICT")
    return True


def _fetch_credential_windows() -> str:
    """Somente Credential Manager do usuario atual; nunca imprime token."""
    if os.name != "nt":
        raise Blocked("CREDENTIAL_UNAVAILABLE")
    from ctypes import wintypes

    class CredentialW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR),
        ]
    try:
        api = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(ctypes.POINTER(CredentialW))]
        api.CredReadW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
        pointer = ctypes.POINTER(CredentialW)()
        if not api.CredReadW(CRED_TARGET, 1, 0, ctypes.byref(pointer)):
            raise Blocked("CREDENTIAL_UNAVAILABLE")
        try:
            length = int(pointer.contents.CredentialBlobSize)
            guard(0 < length <= 8192, "CREDENTIAL_UNAVAILABLE")
            raw = ctypes.string_at(pointer.contents.CredentialBlob, length)
            token = raw.decode("utf-8", errors="strict").strip()
            guard(20 <= len(token) <= 4096 and all(32 < ord(c) < 127 for c in token),
                  "CREDENTIAL_UNAVAILABLE")
            return token
        finally:
            api.CredFree(pointer)
    except Blocked:
        raise
    except Exception:
        raise Blocked("CREDENTIAL_UNAVAILABLE") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("REDIRECT_REJECTED")


def _load_source_id() -> str:
    # Configuracao local confiavel e pre-provisionada. Nenhuma fonte e passada por chat/CLI.
    _no_reparse(SOURCE_CONFIG)
    try:
        with SOURCE_CONFIG.open("rb") as inp:
            data = inp.read(200)
    except OSError:
        raise Blocked("SOURCE_CONFIG_UNAVAILABLE") from None
    try:
        source_id = data.decode("ascii").strip()
    except UnicodeError:
        raise Blocked("SOURCE_ID_UNAPPROVED") from None
    guard(re.fullmatch(r"[A-Za-z0-9_-]{20,100}", source_id) is not None,
          "SOURCE_ID_UNAPPROVED")
    guard(hashlib.sha256(source_id.encode("ascii")).hexdigest() == SOURCE_ID_SHA256,
          "SOURCE_ID_UNAPPROVED")
    return source_id


def _download_private(token: str, source_id: str) -> bytes:
    # O URL esta fixado no codigo; TLS do sistema valida certificado e cadeia.
    import ssl
    url = f"https://www.googleapis.com/drive/v3/files/{source_id}?alt=media&supportsAllDrives=true"
    request = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/octet-stream", "User-Agent": "noteri-store-ingest/1"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
    )
    try:
        with opener.open(request, timeout=30) as resp:
            guard(resp.status == 200 and resp.geturl() == url, "DRIVE_RESPONSE_REJECTED")
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit():
                guard(int(declared) == EXPECTED_BYTES, "SOURCE_SIZE_MISMATCH")
            payload = resp.read(EXPECTED_BYTES + 1)
    except Blocked:
        raise
    except (urllib.error.URLError, OSError, TimeoutError):
        raise Blocked("DRIVE_AUTH_OR_TRANSPORT_FAILED") from None
    guard(len(payload) == EXPECTED_BYTES, "SOURCE_SIZE_MISMATCH")
    guard(hashlib.sha256(payload).hexdigest() == EXPECTED_SHA256,
          "SOURCE_HASH_MISMATCH")
    return payload


def _trusted_root() -> Path:
    root = Path(r"C:\dev\chatgpt-workers\runtime-assets\powerbi-store")
    _no_reparse(root)
    return root


def _receipt(state: str, *, source_sha: str, session_id: str) -> dict:
    return {
        "schema_version": SCHEMA,
        "status": state,
        "environment": "DEV",
        "host": HOST,
        "source_id_digest": SOURCE_ID_SHA256,
        "source_sha": source_sha,
        "file_sha256": EXPECTED_SHA256,
        "file_size": EXPECTED_BYTES,
        "session_id": session_id,
        "correlation_id": CORRELATION,
        "idempotency_key": IDEMPOTENCY,
        "disk_sha256_readback_verified": True,
        "independent_effect_verified": False,
        "transport_ready": False,
        "powerbi_opened": False,
        "data_refreshed": False,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def ingest(*, source_sha: str, session_id: str, root: Path,
           credential_provider: Callable[[], str],
           source_id_provider: Callable[[], str],
           downloader: Callable[[str, str], bytes], host: str,
           platform: str) -> dict:
    """Contrato funcional testavel com dependencias injetadas; nao e entrypoint livre."""
    guard(platform == "nt" and host.casefold() == HOST.casefold(), "NOTERI_WINDOWS_REQUIRED")
    guard(len(source_sha) == 40 and all(c in "0123456789abcdef" for c in source_sha),
          "INVALID_SOURCE_SHA")
    guard(3 <= len(session_id) <= 80 and all(c.isalnum() or c in "-_." for c in session_id),
          "INVALID_SESSION_ID")
    _no_reparse(root)
    # Nunca escrever no checkout Git; runner/Gateway e responsavel pela sessao.
    guard(root.name == "powerbi-store" and root.parent.name == "runtime-assets" and
          root.parent.parent.name == "chatgpt-workers", "ROOT_NOT_ALLOWLISTED")
    target = root / FILE_NAME
    if _check_existing(target):
        return _receipt("ALREADY_PRESENT_AND_VERIFIED", source_sha=source_sha, session_id=session_id)
    source_id = source_id_provider()
    guard(re.fullmatch(r"[A-Za-z0-9_-]{20,100}", source_id) is not None and
          hashlib.sha256(source_id.encode("ascii")).hexdigest() == SOURCE_ID_SHA256,
          "SOURCE_ID_UNAPPROVED")
    token = credential_provider()
    guard(isinstance(token, str) and bool(token), "CREDENTIAL_UNAVAILABLE")
    payload = downloader(token, source_id)
    guard(isinstance(payload, bytes) and len(payload) == EXPECTED_BYTES,
          "SOURCE_SIZE_MISMATCH")
    guard(hashlib.sha256(payload).hexdigest() == EXPECTED_SHA256, "SOURCE_HASH_MISMATCH")
    # Somente depois de autenticar origem e validar os bytes, preparar destino.
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _no_reparse(root)
    temporary = root / ("." + FILE_NAME + "." + secrets.token_hex(10) + ".pending")
    _no_reparse(temporary)
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                               getattr(os, "O_BINARY", 0), 0o600), "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        guard(_sha_of_file(temporary) == (EXPECTED_BYTES, EXPECTED_SHA256),
              "STAGING_READBACK_FAILED")
        # Windows os.rename nao substitui alvo existente; reforco contra overwrite.
        guard(not target.exists() and not target.is_symlink(), "TARGET_CONTENT_CONFLICT")
        os.rename(temporary, target)
        guard(_sha_of_file(target) == (EXPECTED_BYTES, EXPECTED_SHA256),
              "TARGET_READBACK_FAILED")
        return _receipt("INGESTED_AND_VERIFIED", source_sha=source_sha, session_id=session_id)
    except Blocked:
        raise
    except OSError:
        raise Blocked("STAGING_OR_COMMIT_FAILED") from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Ingestao tipada PBIX STORE Noteri DEV")
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args(argv)
    try:
        guard(args.confirm == CONFIRM, "CONFIRMATION_REJECTED")
        result = ingest(source_sha=args.source_sha, session_id=args.session_id,
                        root=_trusted_root(), credential_provider=_fetch_credential_windows,
                        source_id_provider=_load_source_id, downloader=_download_private,
                        host=socket.gethostname(), platform=os.name)
    except Blocked as exc:
        result = {"schema_version": SCHEMA, "status": "BLOCKED", "reason": exc.code,
                  "environment": "DEV", "host": HOST, "correlation_id": CORRELATION,
                  "disk_sha256_readback_verified": False, "independent_effect_verified": False,
                  "transport_ready": False, "powerbi_opened": False, "data_refreshed": False}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["status"] in ("INGESTED_AND_VERIFIED", "ALREADY_PRESENT_AND_VERIFIED") else 2

if __name__ == "__main__":
    sys.exit(main())
