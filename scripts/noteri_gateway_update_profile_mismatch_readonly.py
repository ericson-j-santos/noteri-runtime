#!/usr/bin/env python3
"""Sanitized, read-only source-of-profile comparison (no secret output)."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import socket
import noteri_gateway_authorized_update_preflight_readonly as p
from noteri_ollama_recovery_preflight import source_sha
CORRELATION=re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
SHA40=re.compile(r"[0-9a-f]{40}\Z")
CONFIRM="INSPECT-NOTERI-GATEWAY-PROFILE-DIVERGENCE-READONLY"
def classify(value):
    if value is True: return "TRUE"
    if value is False: return "FALSE"
    if value is None: return "MISSING_OR_NULL"
    return "OTHER_TYPE"
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--expected-head",required=True)
    a.add_argument("--correlation-id",required=True)
    a.add_argument("--confirm",required=True)
    ns=a.parse_args()
    try:
        if (os.name!="nt" or socket.gethostname().casefold()!="noteri"
            or ns.confirm!=CONFIRM
            or not SHA40.fullmatch(ns.expected_head)
            or not CORRELATION.fullmatch(ns.correlation_id)
            or source_sha(Path(__file__).resolve().parents[1])!=ns.expected_head):
            raise ValueError("REQUEST_OR_HOST_MISMATCH")
        policy,_=p.read_stable_object(p.ROOT/"config"/"policy.json")
        receipt,_=p.read_stable_object(p.ROOT/"update-receipt.json")
        if (os.path.lexists(p.ROOT/"update-transaction.json")
            or receipt.get("result")!="HOST_UPDATE_OK"):
            raise ValueError("JOURNAL_OR_RECEIPT_STATE_UNSAFE")
        ans={
            "result":"NOTERI_GATEWAY_PROFILE_DIVERGENCE_READONLY",
            "correlation_id":ns.correlation_id,
            "policy_wsl_inventory": classify(policy.get("noteri_wsl_running_inventory")),
            "receipt_wsl_inventory": classify(receipt.get("noteri_wsl_inventory_profile")),
            "policy_rules_version_matches_installed":policy.get("rules_version")=="1.6.20",
            "receipt_rules_version_matches_installed":receipt.get("rules_version")=="1.6.20",
            "receipt_source_commit_matches_pinned":receipt.get("source_commit")=="11e2e86d0283e83247d8058d05bbabe3dd7cc2c2",
            "journal_present":False,
            "update_applied":False,
            "mutation_performed":False,
        }
        print(json.dumps(ans,sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({"result":"NOTERI_GATEWAY_PROFILE_DIVERGENCE_BLOCKED","mutation_performed":False}))
        return 2
if __name__=="__main__": raise SystemExit(main())
