from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts" / "noteri_capability_contract.py"
SPEC = importlib.util.spec_from_file_location("noteri_capability_contract", PATH)
module = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(module)


def request(**overrides):
    value = {
        "schema_version": module.SCHEMA,
        "capability": "runner.install",
        "target_host": "Noteri",
        "environment": "dev",
        "source_sha": "a" * 40,
        "correlation_id": "runner-install-20261019",
        "idempotency_key": "runner-install-20261019",
        "confirmation": "INSTALL-NOTERI-RUNTIME-RUNNER",
        "params": {"runner_version": "2.338.0"},
    }
    value.update(overrides)
    return value


def validate(value):
    return module.validate_request(
        value,
        capability="runner.install",
        allowed_environments={"local", "dev"},
        expected_source_sha="a" * 40,
        allowed_params={"runner_version"},
        required_params={"runner_version"},
        expected_confirmation="INSTALL-NOTERI-RUNTIME-RUNNER",
    )


def test_positive_contract_and_digest_is_deterministic():
    first = validate(request())
    second = validate(request())
    assert first == second
    assert first["request_sha256"] == module.canonical_request_digest(request())
    assert len(first["request_sha256"]) == 64


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("schema_version", "v0", "schema_version_invalid"),
        ("capability", "sql.hml.probe", "capability_mismatch"),
        ("target_host", "Other", "target_host_mismatch"),
        ("environment", "prod", "environment_not_allowed"),
        ("source_sha", "main", "source_sha_invalid"),
        ("source_sha", "b" * 40, "source_sha_mismatch"),
        ("correlation_id", "bad space", "correlation_id_invalid"),
        ("idempotency_key", "short", "idempotency_key_invalid"),
        ("confirmation", "WRONG", "confirmation_invalid"),
    ],
)
def test_rejects_wrong_binding(field, value, reason):
    payload = request(**{field: value})
    with pytest.raises(module.CapabilityContractError, match=reason):
        validate(payload)


def test_unknown_top_level_field_rejected():
    payload = request()
    payload["extra"] = True
    with pytest.raises(module.CapabilityContractError, match="request_fields_invalid"):
        validate(payload)


def test_unknown_parameter_rejected():
    payload = request()
    payload["params"]["path"] = "C:/other"
    with pytest.raises(module.CapabilityContractError, match="unknown_parameter"):
        validate(payload)


def test_required_parameter_rejected_when_missing():
    payload = request(params={})
    with pytest.raises(module.CapabilityContractError, match="required_parameter_missing"):
        validate(payload)


def test_receipt_is_atomic_and_contains_completion_time(tmp_path):
    target = tmp_path / "receipt.json"
    module.atomic_receipt(target, {"ok": True, "correlation_id": "runner-install-20261019"})
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["ok"] is True
    assert saved["correlation_id"] == "runner-install-20261019"
    assert "completed_at" in saved
    assert not target.with_name(target.name + ".tmp").exists()


def test_atomic_request_does_not_add_receipt_metadata(tmp_path):
    target=tmp_path/"request.json"
    payload={"schema_version":module.SCHEMA,"capability":"runner.install"}
    module.atomic_request(target,payload)
    saved=json.loads(target.read_text(encoding="utf-8"))
    assert saved==payload
    assert "completed_at" not in saved
