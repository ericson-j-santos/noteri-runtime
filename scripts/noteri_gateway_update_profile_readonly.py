#!/usr/bin/env python3
"""Bounded read-only admission for same-profile 6f1 Gateway update on Noteri DEV."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import socket
import hashlib
import noteri_gateway_authorized_update_preflight_readonly as p
from noteri_ollama_recovery_preflight import source_sha

TARGET = "6f1dbb0a3c769f2c31ffa3b97ad57576f26ac27f"
GATEWAY_OLD_SHA = "805c0b4d71fec9690efa6296e9672a5be2e69287d725d15db9e7560d0e943380"
RECEIPT_SHA = "def5a5fc7f7748a61adac626420b3305aeb174f8db6332e48f94ca362393c741"
POLICY_SHA = "d5538a1ec6c6120d020ec9b2bb761f6d74f137d5176a713a74701add9ea4188b"
CONFIRM = "INSPECT-NOTERI-GATEWAY-UPDATE-PROFILE-READONLY"
ID = re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")

class Blocked(RuntimeError): pass

def require(v: bool, why: str) -> None:
    if not v:
        raise Blocked(why)

def inspect() -> dict:
    require(os.name == "nt" and socket.gethostname().casefold() == "noteri",
            "HOST_NOTERI_WINDOWS_REQUIRED")
    root = p.ROOT
    p.require_directory(root)
    require(not os.path.lexists(root / "update-transaction.json"),
            "PENDING_JOURNAL")
    rec, rd = p.read_stable_object(root / "update-receipt.json")
    pol, pd = p.read_stable_object(root / "config" / "policy.json")
    gw = p.require_regular(root / "bin" / "command_gateway.py")
    gh = hashlib.sha256(gw).hexdigest()
    require(rd == RECEIPT_SHA and pd == POLICY_SHA and gh == GATEWAY_OLD_SHA,
            "INSTALLED_BASELINE_SHA_DRIFT")
    require(rec.get("result") == "HOST_UPDATE_OK"
            and rec.get("source_commit") == "11e2e86d0283e83247d8058d05bbabe3dd7cc2c2",
            "RECEIPT_IDENTITY_DRIFT")
    profile = pol.get("noteri_wsl_running_inventory")
    receipt_profile = rec.get("noteri_wsl_inventory_profile")
    require(type(profile) is bool and type(receipt_profile) is bool
            and profile == receipt_profile, "INSTALLED_PROFILE_MISMATCH")
    require(rec.get("rules_version") == "1.6.20",
            "INSTALLED_RULES_VERSION_DRIFT")
    require(p._safe_backup_root(rec.get("backup_dir"))[0],
            "PRIOR_BACKUP_UNVERIFIED")
    require(not os.path.lexists(root / "update-transaction.json"),
            "JOURNAL_CONCURRENTLY_REAPPEARED")
    require(p.read_stable_object(root / "update-receipt.json")[1] == RECEIPT_SHA
            and p.read_stable_object(root / "config" / "policy.json")[1] == POLICY_SHA,
            "RECEIPT_OR_POLICY_CHANGED")
    return {
        "result": "NOTERI_GATEWAY_PROFILE_PREFLIGHT_READONLY",
        "host": "Noteri", "environment": "DEV",
        "target_commit": TARGET,
        "old_gateway_sha256": gh,
        "receipt_sha256": rd,
        "policy_sha256": pd,
        "installed_version": "1.6.20",
        "current_noteri_wsl_profile": profile,
        "target_noteri_wsl_profile": profile,
        "journal_present": False,
        "receipt_is_success": True,
        "previous_backup_present": True,
        "identity_is_administrator": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "mutation_performed": False,
        "installation_authorized_by_preflight": False,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm", required=True)
    ns = parser.parse_args()
    try:
        require(SHA.fullmatch(ns.expected_head) is not None
                and ID.fullmatch(ns.correlation_id) is not None
                and ns.confirm == CONFIRM
                and source_sha(Path(__file__).resolve().parents[1]) == ns.expected_head,
                "SOURCE_ATTESTATION_FAILED")
        result = inspect()
        result["correlation_id"] = ns.correlation_id
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked,p.Blocked,OSError,ValueError) as e:
        reason = str(e) if isinstance(e,(Blocked,p.Blocked)) else "READ_ONLY_PREFLIGHT_ERROR"
        print(json.dumps({"result":"NOTERI_GATEWAY_PROFILE_PREFLIGHT_BLOCKED",
                          "reason": reason,"mutation_performed": False}, sort_keys=True))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
