#!/usr/bin/env python3
"""One-transaction Win32 rollback evidence after failed 6f1 Gateway update.

Read-only. Fixed host/transaction/backup, fixed canonical security helper,
existing update lock with no write/create, stable double reads. No repair.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import noteri_gateway_authorized_update_preflight_readonly as safe
import noteri_gateway_journal_windows_metadata_readonly as meta
import noteri_gateway_journal_binding_readonly as binding
from noteri_ollama_recovery_preflight import source_sha

ROOT=Path(r"C:\dev\chatgpt-command-gateway")
TARGET="6f1dbb0a3c769f2c31ffa3b97ad57576f26ac27f"
TX="7160b6fd6f8842b58643667f38c19b3f"
BACKUP_NAME="backup-20261115-235828-b7f4a69a0f364d7b935ac9e04f2b5641"
PREV_RECEIPT="def5a5fc7f7748a61adac626420b3305aeb174f8db6332e48f94ca362393c741"
PREV_POLICY="d5538a1ec6c6120d020ec9b2bb761f6d74f137d5176a713a74701add9ea4188b"
PREV_GATEWAY="805c0b4d71fec9690efa6296e9672a5be2e69287d725d15db9e7560d0e943380"
CONFIRM="READBACK-NOTERI-GATEWAY-6F1-FAILED-ROLLBACK-READONLY"
ID=re.compile(r"[A-Za-z0-9_.:-]{12,128}\Z")
SHA40=re.compile(r"[0-9a-f]{40}\Z")

class ReadbackBlocked(RuntimeError):pass
def require(value,why):
    if not value:raise ReadbackBlocked(why)

def sha(path):
    return hashlib.sha256(safe.require_regular(path)).hexdigest()

def inspect():
    require(os.name=="nt" and socket.gethostname().casefold()=="noteri",
            "NOTERI_WINDOWS_REQUIRED")
    safe.require_directory(ROOT)
    backup=ROOT/BACKUP_NAME
    safe.require_directory(backup)
    safe.require_directory(backup/"files")
    journal_path=ROOT/"update-transaction.json"
    recovery_path=ROOT/("update-recovery-"+TX+".json")
    receipt_path=ROOT/"update-receipt.json"
    policy_path=ROOT/"config"/"policy.json"
    with meta.existing_exclusive_update_lock(ROOT):
        j,jh=safe.read_stable_object(journal_path)
        failure,fh=safe.read_stable_object(recovery_path)
        receipt,rh=safe.read_stable_object(receipt_path)
        policy,ph=safe.read_stable_object(policy_path)
        manifest,mh=safe.read_stable_object(backup/"rollback-manifest.json")
        require(rh==PREV_RECEIPT and ph==PREV_POLICY
                and sha(ROOT/"bin"/"command_gateway.py")==PREV_GATEWAY,
                "OLD_RUNTIME_OR_RECEIPT_HASH_CHANGED")
        require(receipt.get("result")=="HOST_UPDATE_OK"
                and receipt.get("source_commit")=="11e2e86d0283e83247d8058d05bbabe3dd7cc2c2",
                "OLD_RECEIPT_IDENTITY_INVALID")
        require(j.get("version")==1 and j.get("source_commit")==TARGET
                and j.get("transaction_id")==TX
                and j.get("backup_dir")==str(backup),
                "JOURNAL_BINDING_INVALID")
        require(failure.get("source_commit")==TARGET
                and failure.get("transaction_id")==TX
                and failure.get("backup_dir")==str(backup)
                and failure.get("result")=="HOST_UPDATE_BLOCKED"
                and failure.get("phase")=="install_runtime"
                and failure.get("mutation_started") is True
                and failure.get("rollback_attempted") is True
                and failure.get("rollback_succeeded") is True,
                "FAILED_RECEIPT_ROLLBACK_NOT_PROVEN")
        detail=failure.get("failure")
        require(type(detail) is dict
                and detail.get("destination")=="bin/session_preflight.py"
                and detail.get("operation")=="activate_stage"
                and type(detail.get("os_error")) is dict
                and detail["os_error"].get("winerror")==5
                and detail.get("cause_determined") is False,
                "FAILURE_DIAGNOSTIC_MISMATCH")
        require(manifest.get("version")==2
                and type(manifest.get("entries")) is dict
                and set(manifest["entries"])==binding.legacy.MANAGED
                and os.path.normcase(str(manifest.get("install_root"))) ==
                   os.path.normcase(str(ROOT)),
                "SNAPSHOT_MANIFEST_INVALID")
        helper=meta._fixed_helper()
        complete=0
        for rel,item in sorted(manifest["entries"].items()):
            require(type(item) is dict and type(item.get("existed")) is bool,
                    "SNAPSHOT_ENTRY_INVALID")
            target=ROOT.joinpath(*rel.split("/"))
            saved=backup/"files"/rel
            if item["existed"]:
                require(binding._matched(target,item.get("previous_sha256"),
                                         item.get("previous_size"))
                        and binding._matched(saved,item.get("previous_sha256"),
                                             item.get("previous_size")),
                        "INSTALLED_OR_BACKUP_CONTENT_CHANGED")
                expected=item.get("previous_windows_state")
                require(type(expected) is dict,"WINDOWS_METADATA_MISSING")
                meta._validate_file_security(helper,target,expected)
                meta._validate_file_security(helper,saved,expected)
            else:
                require(not os.path.lexists(target) and not os.path.lexists(saved),
                        "ABSENT_PREVIOUS_FILE_REAPPEARED")
            complete+=1
        require(safe.read_stable_object(journal_path)[1]==jh
                and safe.read_stable_object(recovery_path)[1]==fh
                and safe.read_stable_object(receipt_path)[1]==rh
                and safe.read_stable_object(policy_path)[1]==ph
                and safe.read_stable_object(backup/"rollback-manifest.json")[1]==mh,
                "EVIDENCE_CHANGED_DURING_INSPECTION")
        return {
          "result":"NOTERI_GATEWAY_6F1_ROLLBACK_READBACK_OK",
          "host":"Noteri","environment":"DEV",
          "failed_target_commit":TARGET,
          "failed_transaction":TX,
          "failure_winerror":5,
          "failure_destination":"bin/session_preflight.py",
          "failure_operation":"activate_stage",
          "failure_root_cause_determined":False,
          "rollback_attempted":True,"rollback_succeeded_receipt":True,
          "installed_previous_state_files_verified":complete,
          "saved_previous_state_files_verified":complete,
          "windows_metadata_verified":True,
          "primary_receipt_sha256":rh,
          "failure_receipt_sha256":fh,
          "transaction_journal_sha256":jh,
          "backup_manifest_sha256":mh,
          "gateway_sha256":PREV_GATEWAY,
          "journal_present":True,
          "archive_or_recovery_authorized":False,
          "mutation_performed":False,
        }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--expected-head",required=True)
    p.add_argument("--correlation-id",required=True)
    p.add_argument("--confirm",required=True)
    ns=p.parse_args()
    try:
        require(SHA40.fullmatch(ns.expected_head) is not None
                and ID.fullmatch(ns.correlation_id) is not None
                and ns.confirm==CONFIRM
                and source_sha(Path(__file__).resolve().parents[1])==ns.expected_head,
                "SOURCE_OR_REQUEST_INVALID")
        out=inspect()
        out["correlation_id"]=ns.correlation_id
        print(json.dumps(out,sort_keys=True))
        return 0
    except Exception as e:
        reason=str(e) if isinstance(e,(ReadbackBlocked,safe.Blocked,meta.Blocked,binding.Blocked)) else "READBACK_FAILED"
        print(json.dumps({"result":"NOTERI_GATEWAY_6F1_ROLLBACK_READBACK_BLOCKED",
                           "reason":reason,"mutation_performed":False},sort_keys=True))
        return 3
if __name__=="__main__":raise SystemExit(main())
