from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"scripts"/"noteri_runner_capability.py"
sys.path.insert(0,str(ROOT/"scripts"))
SPEC=importlib.util.spec_from_file_location("noteri_runner_capability_test",PATH)
module=importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


def validated():
    return {
        "source_sha":"a"*40,
        "correlation_id":"runner-install-20261019",
        "idempotency_key":"runner-install-20261019",
        "request_sha256":"b"*64,
        "params":dict(module.EXPECTED_PARAMS),
    }


def test_parameters_are_closed_and_versioned():
    assert module.EXPECTED_PARAMS["runner_version"]=="2.338.0"
    assert module.EXPECTED_PARAMS["runner_name"]=="Noteri-runtime"
    assert module.EXPECTED_PARAMS["repository"]=="ericson-j-santos/noteri-runtime"
    assert module.EXPECTED_PARAMS["persistence"]=="s4u-limited-with-hkcu-fallback"


def test_parameter_drift_is_rejected():
    params=dict(module.EXPECTED_PARAMS)
    params["repository"]="other/repo"
    with pytest.raises(module.CapabilityError,match="runner_parameters_mismatch"):
        module.validate_params(params)


def test_success_requires_api_readback(tmp_path,monkeypatch):
    monkeypatch.setattr(module,"checkpoint_path",lambda key:tmp_path/key/"receipt.json")
    monkeypatch.setattr(module.runner,"install_dedicated",lambda **kwargs:{
        "ok":True,"registered_now":True,"actions_qualified":False,"hml_verified":False})
    monkeypatch.setattr(module,"online_with_retry",lambda:{"runner":{"name":"Noteri-runtime","status":"online"}})
    result=module.execute(validated())
    assert result["status"]=="completed"
    assert result["readback"]["runner"]["status"]=="online"
    assert result["actions_qualified"] is False
    assert result["hml_verified"] is False


def test_readback_failure_does_not_write_success_checkpoint(tmp_path,monkeypatch):
    target=tmp_path/"receipt.json"
    monkeypatch.setattr(module,"checkpoint_path",lambda key:target)
    monkeypatch.setattr(module.runner,"install_dedicated",lambda **kwargs:{"ok":True})
    def fail(): raise module.CapabilityError("runner_api_not_online")
    monkeypatch.setattr(module,"online_with_retry",fail)
    with pytest.raises(module.CapabilityError,match="runner_api_not_online"):
        module.execute(validated())
    assert not target.exists()


def test_replay_revalidates_identity_and_api(tmp_path,monkeypatch):
    target=tmp_path/"receipt.json"
    target.write_text(json.dumps({"request_sha256":"b"*64,"status":"completed"}),encoding="utf-8")
    monkeypatch.setattr(module,"checkpoint_path",lambda key:target)
    monkeypatch.setattr(module.runner,"dedicated_home",lambda:tmp_path)
    monkeypatch.setattr(module.runner,"local_identity",lambda root:{"repository":module.runner.EXPECTED_REPOSITORY})
    monkeypatch.setattr(module,"api_online",lambda:{"runner":{"name":"Noteri-runtime","status":"online"}})
    result=module.execute(validated())
    assert result["replayed"] is True
    assert result["readback"]["runner"]["status"]=="online"


def test_idempotency_conflict_is_blocked(tmp_path,monkeypatch):
    target=tmp_path/"receipt.json";target.write_text(json.dumps({"request_sha256":"c"*64}),encoding="utf-8")
    monkeypatch.setattr(module,"checkpoint_path",lambda key:target)
    with pytest.raises(module.CapabilityError,match="idempotency_conflict"):
        module.execute(validated())
