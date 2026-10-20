#!/usr/bin/env python3
"""Contrato fail-closed para capabilities governadas do host Noteri."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "noteri-capability-request/v1"
EXPECTED_HOST = "Noteri"
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CapabilityContractError(RuntimeError):
    pass


def _require_text(value: Any, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CapabilityContractError(f"{name}_invalid")
    return value


def canonical_request_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_request(
    payload: Mapping[str, Any],
    *,
    capability: str,
    allowed_environments: set[str],
    expected_source_sha: str,
    allowed_params: set[str],
    required_params: set[str] | None = None,
    expected_confirmation: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise CapabilityContractError("request_shape_invalid")
    known = {
        "schema_version", "capability", "target_host", "environment",
        "source_sha", "correlation_id", "idempotency_key", "confirmation", "params",
    }
    if set(payload) != known:
        raise CapabilityContractError("request_fields_invalid")
    if payload.get("schema_version") != SCHEMA:
        raise CapabilityContractError("schema_version_invalid")
    if payload.get("capability") != capability:
        raise CapabilityContractError("capability_mismatch")
    if payload.get("target_host") != EXPECTED_HOST:
        raise CapabilityContractError("target_host_mismatch")
    environment = payload.get("environment")
    if not isinstance(environment, str) or environment not in allowed_environments:
        raise CapabilityContractError("environment_not_allowed")
    source_sha = _require_text(payload.get("source_sha"), "source_sha", SHA40)
    if source_sha != expected_source_sha:
        raise CapabilityContractError("source_sha_mismatch")
    correlation_id = _require_text(payload.get("correlation_id"), "correlation_id", SAFE_ID)
    idempotency_key = _require_text(payload.get("idempotency_key"), "idempotency_key", SAFE_ID)
    if payload.get("confirmation") != expected_confirmation:
        raise CapabilityContractError("confirmation_invalid")
    params = payload.get("params")
    if not isinstance(params, dict):
        raise CapabilityContractError("params_invalid")
    if set(params) - allowed_params:
        raise CapabilityContractError("unknown_parameter")
    missing = (required_params or set()) - set(params)
    if missing:
        raise CapabilityContractError("required_parameter_missing")
    return {
        "schema_version": SCHEMA,
        "capability": capability,
        "target_host": EXPECTED_HOST,
        "environment": environment,
        "source_sha": source_sha,
        "correlation_id": correlation_id,
        "idempotency_key": idempotency_key,
        "params": dict(params),
        "request_sha256": canonical_request_digest(payload),
    }


def atomic_receipt(path: Path, payload: Mapping[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(payload)
    data["completed_at"] = datetime.now(timezone.utc).isoformat()
    encoded = json.dumps(data, sort_keys=True, ensure_ascii=True) + "\n"
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(encoded, encoding="utf-8")
    temp.replace(path)
