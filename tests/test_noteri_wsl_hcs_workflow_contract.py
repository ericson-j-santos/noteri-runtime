"""YAML syntax gate and denial contracts for the one-shot physical HCS workflow.

Uses Ruby's Psych YAML parser on the hosted CI runner, matching the parser
gate used to prevent the earlier Noteri workflow syntax incident.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-wsl-hcs-readonly.yml"
SOURCE = PATH.read_text(encoding="utf-8")


def parse_yaml(source: Path):
    try:
        result = subprocess.run(
            ["ruby", "-rpsych", "-e", "Psych.parse_file(ARGV.fetch(0))", str(source)],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except FileNotFoundError:
        pytest.fail("Ruby Psych parser missing: YAML must not pass unvalidated")
    return result.returncode


def test_yaml_parser_accepts_real_workflow_and_rejects_broken_yaml(tmp_path):
    assert parse_yaml(PATH) == 0
    broken = tmp_path / "broken.yml"
    broken.write_text(SOURCE.replace("jobs:\n", "jobs: [\n", 1), encoding="utf-8")
    assert parse_yaml(broken) != 0


def test_physical_trigger_needs_exact_one_time_owner_marker_and_sha():
    for token in (
        "types: [edited]",
        "github.actor == 'ericson-j-santos'",
        "github.event.pull_request.draft == true",
        "OWNER_NOTERI_HCS_TIMEOUT_RECOVERY_20261026_ONCE",
        "github.event.changes.body.from",
        "NOTERI_HCS_REQUIRED_CI_MISSING",
        "NOTERI_HCS_ALREADY_DISPATCHED",
        "NOTERI_HCS_CONCURRENT_RUN_DENIED",
        "github.rest.actions.listJobsForWorkflowRun" if False else "github.rest.actions.listJobsForWorkflowRun",
        "head_sha:sha",
        "needs: admission",
    ):
        assert token in SOURCE


def test_physical_checkout_and_session_are_sha_bound():
    for token in (
        "fetch-depth: 0",
        "persist-credentials: false",
        "92e8b5c87684212964b24ff3597f9f9f8aea49a6",
        "--require-runner-version-preflight",
        "--expected-head",
        "SESSION_LAUNCH_OK",
        "state_validated",
        "runner_version_preflight.ok",
        "risk','1'",
        "scripts/noteri_wsl_hcs_readonly.py",
        "NOTERI_HCS_INTEGRITY_FAILED",
        "NOTERI_HCS_STATE_READBACK_OK",
    ):
        assert token in SOURCE


def test_skipped_owner_marker_cleanup_run_is_not_false_concurrency():
    assert "y.name==='Governed Noteri HCS observation'" in SOURCE
    assert "['queued','waiting','in_progress'].includes(y.status)" in SOURCE
    assert "j.total_count!==j.jobs.length" in SOURCE
    assert "['in_progress','queued','waiting'].includes(run.status)" not in SOURCE


def test_runner_is_not_generic_paid_host_or_prod():
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in SOURCE
    assert "GITHUB_TOKEN: ''" in SOURCE and "GH_TOKEN: ''" in SOURCE
    assert "permissions:\n  contents: read" in SOURCE
    assert "cancel-in-progress: false" in SOURCE
    assert "workflow_dispatch" not in SOURCE
    assert "ubuntu_distro_running_verified -ne $false" in SOURCE
    assert "posix_transport_verified -ne $false" in SOURCE


def test_only_launcher_gateway_execution_and_no_guest_start():
    for forbidden in (
        "wsl.exe", "systemctl start", "systemctl enable", "sudo ",
        "docker run", "neon.tech", "HcsStartComputeSystem", "HcsCreateProcess",
        "powershell -command", "cmd.exe", "git reset --hard", "git clean -fd",
        "git push", "git fetch --force", "force-push", "merge_pull_request",
    ):
        assert forbidden.casefold() not in SOURCE.casefold()


def test_failed_gateway_is_sanitized_and_still_fails_closed():
    assert "NOTERI_HCS_DENIAL phase=" in SOURCE
    assert "$gatewayExit -ne 0" in SOURCE
    assert "HCS_ENUMERATION_REJECTED" in SOURCE
    assert "HCS_API_UNAVAILABLE" in SOURCE
    assert "throw 'NOTERI_HCS_GATEWAY_BLOCKED'" in SOURCE
    assert "Write-Output $envr.stdout" not in SOURCE
    assert "Write-Output $raw" not in SOURCE


def test_host_readback_requires_actual_unskipped_steps():
    for exact in (
        "j.status==='completed'&&j.conclusion==='success'",
        "s.name==='HCS enumeration through risk1 Command Gateway'",
        "s.name==='Independent Git state readback through Gateway'",
        "s.conclusion==='success'",
        "v.ubuntu_distro_running_verified!==false",
        "v.posix_transport_verified!==false",
        "v.guest_started!==false",
        "NOTERI_HCS_NOT_REAL_HOST_JOB",
    ):
        assert exact in SOURCE
