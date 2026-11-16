"""Contratos negativos do workflow de coleta de aprovação, sem host ou rede."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/noteri-worker-pool-inplace-maintenance.yml"
ENV = "noteri-worker-pool-maintenance-dev"


def contract():
    raw = WORKFLOW.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    # PyYAML defaults to YAML 1.1; a literal 'on' key is parsed as True.
    trigger = data.get("on", data.get(True))
    return raw, data, trigger


def test_manual_only_trigger_without_mutating_host():
    raw, data, trigger = contract()
    assert set(trigger) == {"workflow_dispatch"}
    assert set(trigger["workflow_dispatch"]["inputs"]) == {
        "expected_workflow_sha", "correlation_id"
    }
    assert raw.count("workflow_dispatch:") == 1
    assert "\n  push:" not in raw
    assert "\n  pull_request:" not in raw
    assert "\n  schedule:" not in raw
    assert data["permissions"] == {"contents": "read"}


def test_job_is_strictly_on_hosted_runner_with_protected_environment_name():
    _, data, _ = contract()
    assert list(data["jobs"]) == ["approval-evidence-only"]
    job = data["jobs"]["approval-evidence-only"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["environment"] == {"name": ENV}
    assert job["timeout-minutes"] == 3
    assert "github.repository == 'ericson-j-santos/noteri-runtime'" in job["if"]
    assert "github.ref == 'refs/heads/main'" in job["if"]
    assert "github.actor == 'ericson-j-santos'" in job["if"]
    assert "github.triggering_actor == 'ericson-j-santos'" in job["if"]
    assert data["concurrency"]["cancel-in-progress"] is False


def test_steps_reject_sha_replay_and_correlation_invalidity():
    _, data, _ = contract()
    steps = data["jobs"]["approval-evidence-only"]["steps"]
    assert len(steps) == 2
    step = steps[0]
    assert step["shell"] == "bash"
    assert step["env"]["WORKFLOW_SHA"] == "${{ github.sha }}"
    assert step["env"]["REQUESTED_SHA"] == "${{ inputs.expected_workflow_sha }}"
    assert step["env"]["RUN_ATTEMPT"] == "${{ github.run_attempt }}"
    assert "set -euo pipefail" in step["run"]
    assert '"$WORKFLOW_SHA" != "$REQUESTED_SHA"' in step["run"]
    assert '"$RUN_ATTEMPT" != \'1\'' in step["run"]
    assert "NOTERI_APPROVAL_REVIEW_REPLAY_BLOCKED" in step["run"]


def test_no_physical_host_or_execution_or_unbounded_permissions():
    raw, data, _ = contract()
    assert "self-hosted" not in raw
    assert "noteri, reqsys-dev" not in raw
    assert "secrets." not in raw
    assert "GH_TOKEN" not in raw
    assert "GITHUB_TOKEN" not in raw
    assert "python3 " not in raw
    assert "schtasks " not in raw
    assert "docker " not in raw
    assert "sudo " not in raw
    assert "command_gateway.py" not in raw
    assert "--risk" not in raw
    assert "--env" not in raw
    assert "NOTERI_POOL_MAINTENANCE_APPROVED_SHA" not in raw
    assert "execution_authorized=true" not in raw
    assert "write" not in str(data["permissions"])
    assert "no host, Gateway, token, maintenance, or execution authorization" in raw


def execute_review_step(**overrides):
    """Run precisely the harmless shell guard against synthetic dispatch metadata."""
    import os
    import subprocess

    _, data, _ = contract()
    step = data["jobs"]["approval-evidence-only"]["steps"][0]
    values = {
        "WORKFLOW_SHA": "a" * 40,
        "REQUESTED_SHA": "a" * 40,
        "CORRELATION_ID": "noteri42-approval-review-20261116",
        "RUN_ID": "12345",
        "RUN_ATTEMPT": "1",
    }
    values.update(overrides)
    return subprocess.run(
        ["bash", "-c", step["run"]],
        env={**os.environ, **values},
        text=True, capture_output=True, check=False, timeout=5,
    )


def test_shell_positive_is_only_evidence_no_maintenance():
    result = execute_review_step()
    assert result.returncode == 0
    assert "NOTERI_REVIEW_EVIDENCE_ONLY" in result.stdout
    assert "MAINTENANCE" not in result.stdout


def test_shell_rejects_wrong_sha():
    result = execute_review_step(REQUESTED_SHA="b" * 40)
    assert result.returncode != 0
    assert "SHA_MISMATCH" in result.stderr


def test_shell_rejects_invalid_sha_shape():
    result = execute_review_step(REQUESTED_SHA="a" * 39)
    assert result.returncode != 0
    assert "SHA_MISMATCH" in result.stderr


def test_shell_rejects_replay_attempt():
    result = execute_review_step(RUN_ATTEMPT="2")
    assert result.returncode != 0
    assert "REPLAY_BLOCKED" in result.stderr


def test_shell_rejects_bad_correlation():
    result = execute_review_step(CORRELATION_ID="short")
    assert result.returncode != 0
    assert "CORRELATION_INVALID" in result.stderr


def test_shell_rejects_bad_run_id():
    result = execute_review_step(RUN_ID="0")
    assert result.returncode != 0
    assert "REPLAY_BLOCKED" in result.stderr
