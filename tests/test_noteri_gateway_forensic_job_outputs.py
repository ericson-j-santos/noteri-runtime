"""Validação do transporte de recibo entre jobs sem armazenar artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-gateway-forensic-readonly.yml"


def _jobs():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _transport_step():
    return next(
        step for step in _jobs()["independent_readback"]["steps"]
        if "Check same-run job output SHA-256" in step["name"]
    )


def _payload():
    return json.dumps(
        {"result": "NOTERI_GATEWAY_FORENSIC_READONLY",
         "journal_sha256": "a" * 64, "host_ready": False,
         "metadata_assessment": "MATCH"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _run_transport(tmp_path, *, content=None, digest=None):
    content = _payload() if content is None else content
    encoded = base64.b64encode(content).decode() if isinstance(content, bytes) else content
    expected = hashlib.sha256(_payload()).hexdigest() if digest is None else digest
    env = dict(os.environ, RECEIPT_B64=encoded, RECEIPT_SHA256=expected)
    return subprocess.run(
        ["bash", "-c", _transport_step()["run"]],
        cwd=tmp_path, env=env, text=True, capture_output=True, check=False, timeout=20,
    )


def test_transport_contract_is_single_use_manual_without_artifact_quota():
    raw = WORKFLOW.read_text(encoding="utf-8")
    jobs = _jobs()
    inspect = jobs["inspect"]
    assert inspect["runs-on"] == ["self-hosted", "Windows", "X64", "noteri", "reqsys-dev"]
    assert inspect["outputs"] == {
        "receipt_b64": "${{ steps.forensic.outputs.receipt_b64 }}",
        "receipt_sha256": "${{ steps.forensic.outputs.receipt_sha256 }}",
    }
    assert jobs["independent_readback"]["needs"] == "inspect"
    assert jobs["independent_readback"]["runs-on"] == "ubuntu-latest"
    assert _transport_step()["env"] == {
        "RECEIPT_B64": "${{ needs.inspect.outputs.receipt_b64 }}",
        "RECEIPT_SHA256": "${{ needs.inspect.outputs.receipt_sha256 }}",
    }
    assert "  workflow_dispatch:" in raw
    assert "  push:" not in raw and "  schedule:" not in raw
    assert "upload-artifact@" not in raw
    assert "download-artifact@" not in raw
    assert "--risk', '1'" in raw
    assert "--require-runner-version-preflight" in raw
    assert "SESSION_LAUNCH_OK" in raw and "state_validated" in raw
    assert "update_command_gateway_host.py" not in raw
    assert "NOTERI_GATEWAY_FORENSIC_JOB_OUTPUT_SHA256_OK" in raw
    assert "NOTERI_GATEWAY_FORENSIC_INDEPENDENT_READBACK_OK" in raw
    assert "gh api" in raw and "runner_name" in raw
    assert "GITHUB_STEP_SUMMARY" in raw
    assert "8192" in raw and "12000" in raw


@pytest.mark.skipif(os.name == "nt", reason="Bash transport runs in Linux hosted readback")
def test_output_hash_roundtrip_in_actual_bash_consumer(tmp_path):
    result = _run_transport(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "NOTERI_GATEWAY_FORENSIC_JOB_OUTPUT_SHA256_OK" in result.stdout
    assert (tmp_path / "_forensic_readback/noteri-gateway-forensic.json").read_bytes() == _payload()


@pytest.mark.skipif(os.name == "nt", reason="Bash transport runs in Linux hosted readback")
@pytest.mark.parametrize("payload,digest", [
    ("", None),
    ("not_base64!!!", None),
    (b"content-modified", None),
    (None, "f" * 64),
    (None, "INVALID"),
    (b"x" * 9000, hashlib.sha256(b"x" * 9000).hexdigest()),
])
def test_invalid_receipt_or_digest_fails_closed(tmp_path, payload, digest):
    result = _run_transport(tmp_path, content=payload, digest=digest)
    assert result.returncode != 0
    assert "NOTERI_GATEWAY_FORENSIC_JOB_OUTPUT_SHA256_OK" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="jq summary verification belongs to Ubuntu hosted validator")
def test_divergent_file_is_visible_in_sanitized_readback(tmp_path):
    import re
    readback = _jobs()["independent_readback"]["steps"][-1]["run"]
    assert "metadata_states" in readback
    assert "GITHUB_RUN_ID" in readback and "RECEIPT_SHA256" in readback
    assert "to_entries | sort_by(.key)" in readback
    projection = re.search(r"jq -c '(\{[^']+\})'", readback, re.DOTALL)
    assert projection is not None
    report = {
        "result": "NOTERI_GATEWAY_FORENSIC_READONLY",
        "metadata_assessment": "DIVERGENT",
        "host_ready": False, "recovery_authorized": False,
        "metadata_states": {
            "bin/command_gateway.py": {
                "current": False, "backup": True, "preexisting": True
            },
            "config/policy.json": {
                "current": True, "backup": True, "preexisting": True
            },
        },
    }
    completed = subprocess.run(
        ["jq", "-c", projection.group(1)],
        input=json.dumps(report), text=True, capture_output=True, timeout=10, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    persisted = json.loads(completed.stdout)
    assert persisted["metadata_assessment"] == "DIVERGENT"
    assert persisted["metadata_states"]["bin/command_gateway.py"]["current"] is False
    assert persisted["host_ready"] is False
    assert persisted["recovery_authorized"] is False


def test_ci_has_two_real_hosted_jobs_and_negative_controls():
    source = (WORKFLOW.parent / "ci.yml").read_text(encoding="utf-8")
    spec = yaml.safe_load(source)["jobs"]
    a, b = spec["forensic_synthetic_windows"], spec["forensic_synthetic_linux"]
    assert a["runs-on"] == "windows-latest"
    assert b["runs-on"] == "ubuntu-latest"
    assert b["needs"] == "forensic_synthetic_windows"
    assert a["outputs"]["receipt_b64"] == "${{ steps.produce.outputs.receipt_b64 }}"
    assert a["outputs"]["receipt_sha256"] == "${{ steps.produce.outputs.receipt_sha256 }}"
    assert b["env"]["RECEIPT_B64"] == "${{ needs.forensic_synthetic_windows.outputs.receipt_b64 }}"
    assert b["env"]["RECEIPT_SHA256"] == "${{ needs.forensic_synthetic_windows.outputs.receipt_sha256 }}"
    assert "MISSING_OUTPUT_FALSE_POSITIVE" in b["steps"][-1]["run"]
    assert "TAMPERED_OUTPUT_FALSE_POSITIVE" in b["steps"][-1]["run"]
    assert "FORENSIC_SYNTHETIC_CROSS_JOB_READBACK_OK" in b["steps"][-1]["run"]
    assert "upload-artifact" not in source and "download-artifact" not in source
