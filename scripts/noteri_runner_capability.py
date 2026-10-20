#!/usr/bin/env python3
"""Capability tipada para instalar/recuperar o runner dedicado do noteri-runtime."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import noteri_actions_admission as admission
import noteri_capability_contract as contract
import noteri_runner_reregister as runner

CAPABILITY="runner.install"
CONFIRM="INSTALL-NOTERI-RUNTIME-RUNNER"
REQUEST_LIMIT=64*1024
EXPECTED_PARAMS={
    "runner_version":runner.RUNNER_VERSION,
    "package_sha256":runner.RUNNER_PACKAGE_SHA256,
    "repository":runner.EXPECTED_REPOSITORY,
    "runner_name":runner.EXPECTED_NAME,
    "labels":list(runner.EXPECTED_LABELS),
    "persistence":"s4u-limited-with-hkcu-fallback",
}


class CapabilityError(RuntimeError):
    pass


def repo_head()->str:
    root=Path(__file__).resolve().parents[1]
    cp=subprocess.run(["git","-C",str(root),"rev-parse","HEAD"],capture_output=True,
        text=True,encoding="utf-8",errors="replace",timeout=20,check=False)
    value=cp.stdout.strip()
    if cp.returncode!=0 or re.fullmatch(r"[0-9a-f]{40}",value) is None:
        raise CapabilityError("source_sha_unavailable")
    return value


def read_request(path:Path)->dict[str,Any]:
    if path.is_symlink() or not path.is_file() or not 0<path.stat().st_size<=REQUEST_LIMIT:
        raise CapabilityError("request_file_invalid")
    try: value=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc:
        raise CapabilityError("request_json_invalid") from exc
    if not isinstance(value,dict): raise CapabilityError("request_shape_invalid")
    return value


def checkpoint_path(key:str)->Path:
    local=os.environ.get("LOCALAPPDATA")
    if not local: raise CapabilityError("localappdata_missing")
    return Path(local)/"ReqSys"/"NoteriCapabilities"/CAPABILITY/key/"receipt.json"


def api_online()->dict[str,Any]:
    observation=admission.inspect(admission.GitHubRead())
    primary=observation["registries"][0]
    rows=[item for item in primary.get("noteri_runners",[])
          if item.get("name")==runner.EXPECTED_NAME and item.get("eligible") is True]
    if len(rows)!=1: raise CapabilityError("runner_api_not_online")
    return {"runner":rows[0],"registry_total":primary.get("total_count")}


def online_with_retry(seconds:int=30)->dict[str,Any]:
    deadline=time.monotonic()+seconds
    last=None
    while time.monotonic()<deadline:
        try: return api_online()
        except Exception as exc:
            last=exc;time.sleep(2)
    raise CapabilityError(str(last) if isinstance(last,CapabilityError) else "runner_api_not_online")


def validate_params(params:dict[str,Any])->None:
    if params!=EXPECTED_PARAMS: raise CapabilityError("runner_parameters_mismatch")


def execute(validated:dict[str,Any])->dict[str,Any]:
    validate_params(validated["params"])
    checkpoint=checkpoint_path(validated["idempotency_key"])
    if checkpoint.is_file():
        try: previous=json.loads(checkpoint.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError) as exc: raise CapabilityError("checkpoint_invalid") from exc
        if previous.get("request_sha256")!=validated["request_sha256"]:
            raise CapabilityError("idempotency_conflict")
        identity=runner.local_identity(runner.dedicated_home())
        if identity is None: raise CapabilityError("checkpoint_identity_missing")
        try: online=api_online()
        except CapabilityError:
            runner.ensure_listener(runner.dedicated_home())
            online=online_with_retry()
        return {**previous,"replayed":True,"readback":online}

    result=runner.install_dedicated(source_sha=validated["source_sha"],
        correlation_id=validated["correlation_id"],idempotency_key=validated["idempotency_key"])
    online=online_with_retry()
    output={**result,"status":"completed","capability":CAPABILITY,
        "source_sha":validated["source_sha"],"correlation_id":validated["correlation_id"],
        "idempotency_key":validated["idempotency_key"],"request_sha256":validated["request_sha256"],
        "readback":online,"replayed":False,"actions_qualified":False,"hml_verified":False}
    contract.atomic_receipt(checkpoint,output)
    return output


def emit_request(*,path:Path,source_sha:str,correlation_id:str,idempotency_key:str,confirm:str)->dict[str,Any]:
    payload={
        "schema_version":contract.SCHEMA,
        "capability":CAPABILITY,
        "target_host":"Noteri",
        "environment":"dev",
        "source_sha":source_sha,
        "correlation_id":correlation_id,
        "idempotency_key":idempotency_key,
        "confirmation":confirm,
        "params":dict(EXPECTED_PARAMS),
    }
    contract.validate_request(payload,capability=CAPABILITY,
        allowed_environments={"local","dev"},expected_source_sha=source_sha,
        allowed_params=set(EXPECTED_PARAMS),required_params=set(EXPECTED_PARAMS),
        expected_confirmation=CONFIRM)
    contract.atomic_receipt(path,payload)
    return payload


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=["emit","execute"])
    p.add_argument("--request",type=Path,required=True)
    p.add_argument("--receipt",type=Path)
    p.add_argument("--source-sha")
    p.add_argument("--correlation-id")
    p.add_argument("--idempotency-key")
    p.add_argument("--confirm")
    a=p.parse_args()
    try:
        sha=repo_head()
        if a.mode=="emit":
            result=emit_request(path=a.request,source_sha=a.source_sha or "",
                correlation_id=a.correlation_id or "",idempotency_key=a.idempotency_key or "",
                confirm=a.confirm or "")
            print(json.dumps({"status":"request_emitted","request_sha256":contract.canonical_request_digest(result),
                "source_sha":sha,"capability":CAPABILITY},sort_keys=True));return 0
        if a.receipt is None: raise CapabilityError("receipt_required")
        raw=read_request(a.request)
        validated=contract.validate_request(raw,capability=CAPABILITY,
            allowed_environments={"local","dev"},expected_source_sha=sha,
            allowed_params=set(EXPECTED_PARAMS),required_params=set(EXPECTED_PARAMS),
            expected_confirmation=CONFIRM)
        result=execute(validated)
        contract.atomic_receipt(a.receipt,result)
        print(json.dumps(result,sort_keys=True,ensure_ascii=True));return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,(CapabilityError,contract.CapabilityContractError,runner.BootstrapError,admission.Blocked)) else type(exc).__name__
        blocked={"status":"blocked","code":code,"capability":CAPABILITY,
            "actions_qualified":False,"hml_verified":False,"production_touched":False}
        contract.atomic_receipt(a.receipt,blocked)
        print(json.dumps(blocked,sort_keys=True));return 3


if __name__=="__main__":
    raise SystemExit(main())
