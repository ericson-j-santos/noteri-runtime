#!/usr/bin/env python3
"""Inventário forense estritamente somente leitura da falha do Gateway Noteri.

Não recupera journal, permissões ou runtime. Não acessa Linux nem PostgreSQL.
Publica apenas digests e booleanos; nunca SIDs, DACL, conteúdo de ADS ou caminhos.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from typing import Any

try:
    from scripts import noteri_gateway_failure_readback as baseline
except ModuleNotFoundError:
    import noteri_gateway_failure_readback as baseline

ORIGINAL_RECEIPT_SHA256 = "4a4eaa3e9ca99afa053c371f9974da59c9f867a1f249b36dd79450e841e830bf"
ORIGINAL_MANIFEST_SHA256 = "f415f09b37ef30ac765f3616810c45bb8b99d018aa3a59b3a1b349aa7c558209"
FAILED_RULES_SHA = "7d6ec0742ce9570408e8f3673a4f3c65c6777eb0"
ROLLBACK_V2_SHA256 = "2a689e8d3696368c08128da2b3ac4c1f15760005462de615f9b27d2e233f6e09"
CANONICAL_HELPER_SHA256 = "73ef3c091a16a261dfe71fa0ac7bb2e2c6a7f07bdfa3bc592c44855751c92329"
WINDOWS_CONTRACT = "windows-owner-group-dacl-ads-v1"
TX_ID = re.compile(r"[0-9a-f]{32}\Z")


def _canonical_helper(path: Path) -> Any:
    """Carrega somente código canônico por nome e SHA-256 fixados."""
    if tuple(path.parts[-3:]) != ("_rules", "scripts", "install_command_gateway_host.py"):
        raise baseline.ReadbackBlocked("CANONICAL_HELPER_LOCATION_INVALID")
    raw = baseline._regular(path, limit=128 * 1024)
    if hashlib.sha256(raw).hexdigest() != CANONICAL_HELPER_SHA256:
        raise baseline.ReadbackBlocked("CANONICAL_HELPER_HASH_INVALID")
    spec = importlib.util.spec_from_file_location("_noteri_pinned_windows_metadata", path)
    if spec is None or spec.loader is None:
        raise baseline.ReadbackBlocked("CANONICAL_HELPER_LOAD_BLOCKED")
    helper = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(helper)
    except Exception:
        raise baseline.ReadbackBlocked("CANONICAL_HELPER_LOAD_BLOCKED") from None
    if hashlib.sha256(baseline._regular(path, limit=128 * 1024)).hexdigest() != CANONICAL_HELPER_SHA256:
        raise baseline.ReadbackBlocked("CANONICAL_HELPER_CHANGED")
    return helper


def inspect(root: Path, helper_path: Path) -> dict[str, Any]:
    """Examina um único incidente atestado; não tenta qualquer recuperação."""
    old = baseline.inventory(root, ORIGINAL_RECEIPT_SHA256, ORIGINAL_MANIFEST_SHA256)
    if (
        old["receipt_result"] != "HOST_UPDATE_BLOCKED"
        or old["source_commit"] != FAILED_RULES_SHA
        or old["manifest_version"] != 2
        or old["manifest_sha256"] != ROLLBACK_V2_SHA256
        or old["phase"] != "install_runtime"
        or old["failure_type"] != "PermissionError"
        or old["mutation_started"] is not True
        or old["rollback_attempted"] is not True
    ):
        raise baseline.ReadbackBlocked("INCIDENT_BASELINE_DIVERGENT")
    receipt, receipt_digest = baseline._json(root / "update-receipt.json")
    backup = Path(receipt["backup_dir"])
    manifest, manifest_digest = baseline._json(backup / "rollback-manifest.json")
    if (
        manifest_digest != ROLLBACK_V2_SHA256
        or manifest.get("metadata_contract") != WINDOWS_CONTRACT
        or set(manifest["entries"]) != baseline.MANAGED
    ):
        raise baseline.ReadbackBlocked("WINDOWS_ROLLBACK_CONTRACT_INVALID")

    journal, journal_digest = baseline._json(root / "update-transaction.json")
    if (
        journal.get("version") != 1
        or not isinstance(journal.get("transaction_id"), str)
        or not TX_ID.fullmatch(journal["transaction_id"])
        or journal.get("transaction_id") != receipt.get("transaction_id")
        or journal.get("source_commit") != FAILED_RULES_SHA
        or journal.get("backup_dir") != receipt.get("backup_dir")
    ):
        raise baseline.ReadbackBlocked("JOURNAL_BINDING_INVALID")

    helper = _canonical_helper(helper_path)
    states: dict[str, dict[str, bool]] = {}
    checked = 0
    for name in sorted(baseline.MANAGED):
        entry = manifest["entries"][name]
        previous_content = old["managed_states"][name]["previous_content"]
        if not entry["existed"]:
            states[name] = {"current": bool(previous_content), "backup": True, "preexisting": False}
            continue
        checked += 1
        expected = entry.get("previous_windows_state")
        try:
            helper._validate_windows_persisted_state(expected, name)
        except Exception:
            raise baseline.ReadbackBlocked("ROLLBACK_METADATA_SCHEMA_INVALID") from None
        try:
            current = helper._windows_persisted_file_state(root.joinpath(*name.split("/")))
            saved = helper._windows_persisted_file_state(backup / "files" / name)
            current_ok = helper._windows_persisted_state_equivalent(expected, current)
            saved_ok = helper._windows_persisted_state_equivalent(expected, saved)
        except Exception:
            raise baseline.ReadbackBlocked("WINDOWS_METADATA_READ_BLOCKED") from None
        states[name] = {
            "current": bool(previous_content and current_ok),
            "backup": bool(saved_ok),
            "preexisting": True,
        }

    if (
        baseline._json(root / "update-receipt.json")[1] != receipt_digest
        or baseline._json(backup / "rollback-manifest.json")[1] != manifest_digest
        or baseline._json(root / "update-transaction.json")[1] != journal_digest
        or baseline.inventory(root, ORIGINAL_RECEIPT_SHA256, ORIGINAL_MANIFEST_SHA256) != old
    ):
        raise baseline.ReadbackBlocked("FORENSIC_EVIDENCE_CHANGED")
    all_current = all(value["current"] for value in states.values())
    all_backup = all(value["backup"] for value in states.values())
    return {
        "result": "NOTERI_GATEWAY_FORENSIC_READONLY",
        "forensic_contract": "noteri-gateway-journal-windows-v1",
        "incident_rules_sha": FAILED_RULES_SHA,
        "rollback_manifest_sha256": manifest_digest,
        "journal_sha256": journal_digest,
        "journal_bound_to_incident": True,
        "journal_present": True,
        "metadata_contract": WINDOWS_CONTRACT,
        "metadata_checked_files": checked,
        "metadata_states": states,
        "all_previous_content": old["all_previous_content"],
        "all_previous_windows_metadata": all_current,
        "backup_windows_metadata_intact": all_backup,
        "metadata_assessment": "MATCH" if all_current and all_backup else "DIVERGENT",
        "recovery_authorized": False,
        "host_ready": False,
        "managed_runtime_changed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-helper-path", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = inspect(baseline.ROOT, args.canonical_helper_path)
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, baseline.ReadbackBlocked) else "HOST_READ_FAILED"
        print(json.dumps({"result": "NOTERI_GATEWAY_FORENSIC_BLOCKED", "reason": reason}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
