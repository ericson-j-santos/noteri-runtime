#!/usr/bin/env python3
"""Typed, single-action Noteri DEV Gateway journal archive.

The only mutable effect is the recover(apply=True) fixed journal -> its
pre-pinned rollback-backup archive. Never accepts shell, arbitrary paths, URLs,
a second host, another receipt or another journal. Intended to run only within
a SESSION_LAUNCH_OK Command Gateway session, with matching risk authorization.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import socket
import sys

import noteri_gateway_journal_archive_reversible as archive
import noteri_gateway_journal_windows_metadata_readonly as metadata
import noteri_gateway_authorized_update_preflight_readonly as safe
from noteri_ollama_recovery_preflight import source_sha

ACTION = "noteri.gateway.journal.archive-fixed.v1"
HOST = "Noteri"
ENVIRONMENT = "DEV"
JOURNAL = "757ec16e15cf260b24438ab5e7f674eb0b15b6f0a7318dc27aeed6cfbf76c8d0"
RECEIPT = "def5a5fc7f7748a61adac626420b3305aeb174f8db6332e48f94ca362393c741"
BACKUP = "be7e55cbf943ce624df2528f99358140d304abe5a5b1888e19183166afc53be1"
EXPECTED_DESTINATION = "recovered-update-transaction-50227f5817504ca4b328a962a076d673.json"
CONFIRM = "AUTHORIZE_FIXED_REVERSIBLE_NOTERI_DEV_JOURNAL_757EC16E"
CORRELATION = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
KEY = re.compile(r"noteri-journal-757ec16e-[A-Za-z0-9_.:-]{8,80}\Z")


class AdmissionBlocked(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionBlocked(code)


def run_typed(request: dict, *, apply: bool = False) -> dict:
    """All exact, signed-off request fields checked before ANY apply=True call."""
    require(type(request) is dict, "REQUEST_NOT_OBJECT")
    exact = {
        "schema_version", "action_id", "host", "environment", "source_head",
        "journal_sha256", "receipt_sha256", "backup_manifest_sha256",
        "archive_filename", "correlation_id", "idempotency_key",
        "confirm", "max_extra_cost_brl", "rollback_contract",
    }
    require(set(request) == exact, "REQUEST_KEYS_INVALID")
    require(request["schema_version"] == 1 and
            type(request["schema_version"]) is int, "SCHEMA_INVALID")
    require(request["action_id"] == ACTION
            and request["host"] == HOST
            and request["environment"] == ENVIRONMENT
            and request["journal_sha256"] == JOURNAL
            and request["receipt_sha256"] == RECEIPT
            and request["backup_manifest_sha256"] == BACKUP
            and request["archive_filename"] == EXPECTED_DESTINATION,
            "ACTION_SCOPE_MISMATCH")
    require(request["confirm"] == CONFIRM, "AUTHORIZATION_CONFIRMATION_MISSING")
    require(request["max_extra_cost_brl"] == "0.00" and
            request["rollback_contract"] == "win32-same-volume-verified-rollback-v1",
            "COST_OR_ROLLBACK_CONTRACT_MISMATCH")
    require(type(request["correlation_id"]) is str
            and CORRELATION.fullmatch(request["correlation_id"]) is not None
            and type(request["idempotency_key"]) is str
            and KEY.fullmatch(request["idempotency_key"]) is not None,
            "CORRELATION_OR_IDEMPOTENCY_INVALID")
    require(type(request["source_head"]) is str
            and SHA40.fullmatch(request["source_head"]) is not None,
            "SOURCE_HEAD_INVALID")
    require(os.name == "nt" and socket.gethostname().casefold() == HOST.casefold()
            and sys.dont_write_bytecode is True, "NOTERI_WINDOWS_BYTECODE_POLICY_DENIED")
    actual_head = source_sha(Path(__file__).resolve().parents[1])
    require(actual_head == request["source_head"], "CHECKOUT_HEAD_MISMATCH")
    # Installed Gateway enforces the checked-out worktree, session snapshot,
    # risk level, clean tree and expected HEAD *outside* this script.
    result = archive.recover(apply=apply)
    require(result.get("archive_name") == EXPECTED_DESTINATION
            and result.get("journal_sha256") == JOURNAL
            and result.get("receipt_sha256") == RECEIPT,
            "ARCHIVE_READBACK_IDENTITY_INVALID")
    allowed_results = ({"JOURNAL_ARCHIVED_VERIFIED", "JOURNAL_ALREADY_ARCHIVED_VERIFIED"}
                       if apply else {"JOURNAL_ARCHIVE_PREPARED_READONLY"})
    require(result.get("result") in allowed_results and
            bool(result.get("archived")) is apply and
            (not result.get("mutation_performed") or apply),
            "ARCHIVE_EXECUTION_POSTCONDITION_INVALID")
    out = {
        "schema_version": 1,
        "action_id": ACTION,
        "host": HOST,
        "environment": ENVIRONMENT,
        "source_head": actual_head,
        "journal_sha256": JOURNAL,
        "receipt_sha256": RECEIPT,
        "archive_filename": EXPECTED_DESTINATION,
        "correlation_id": request["correlation_id"],
        "idempotency_key": request["idempotency_key"],
        "result": result["result"],
        "mutation_performed": bool(result["mutation_performed"]),
        "archived": bool(result["archived"]),
        "update_lock_held": bool(result["update_lock_held"]),
        "backups_verified": result.get("backups_verified"),
        "rollback_on_failure_implemented": True,
    }
    return out


def decode_closed_request(value: str) -> dict:
    require(type(value) is str and 0 < len(value) <= 8192,
            "REQUEST_BASE64_LENGTH_INVALID")
    try:
        payload = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdmissionBlocked("REQUEST_BASE64_INVALID") from exc
    require(0 < len(payload) <= 4096, "REQUEST_JSON_SIZE_INVALID")

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for name, val in pairs:
            require(name not in result, "DUPLICATE_REQUEST_KEY")
            result[name] = val
        return result

    try:
        data = json.loads(
            payload.decode("utf-8"), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(
                AdmissionBlocked("INVALID_JSON_CONSTANT")),
        )
    except (ValueError, UnicodeError) as exc:
        raise AdmissionBlocked("REQUEST_JSON_INVALID") from exc
    require(type(data) is dict, "REQUEST_NOT_OBJECT")
    return data


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--request-b64", required=True)
    p.add_argument("--apply", action="store_true")
    args = p.parse_args()
    try:
        request = decode_closed_request(args.request_b64)
        result = run_typed(request, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AdmissionBlocked, archive.RecoveryBlocked, metadata.Blocked,
            safe.Blocked, ValueError, OSError) as exc:
        code = (str(exc) if isinstance(exc, (AdmissionBlocked, archive.RecoveryBlocked,
                                             metadata.Blocked, safe.Blocked))
                else "NOTERI_ARCHIVE_EXECUTION_BLOCKED")
        print(json.dumps({
            "result": "NOTERI_ARCHIVE_EXECUTION_BLOCKED",
            "reason": code, "mutation_completeness_unconfirmed": True,
        }, sort_keys=True))
        return 28


if __name__ == "__main__":
    raise SystemExit(main())
