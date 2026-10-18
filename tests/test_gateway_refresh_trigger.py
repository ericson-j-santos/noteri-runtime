import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/noteri-command-gateway-refresh.yml"
SCRIPT = ROOT / "scripts/noteri_gateway_refresh.py"


def test_gateway_refresh_has_narrow_push_trigger():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "  workflow_dispatch:" in text
    assert "  push:" in text
    assert "    branches: [main]" in text
    assert "      - '.github/triggers/noteri-command-gateway-refresh'" in text
    assert "repository_dispatch" not in text
    assert "permissions:\n  contents: read" in text


def test_gateway_refresh_readback_matches_script_contract():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")

    def script_constant(name):
        matches = re.findall(
            rf'^{name}\s*=\s*"([^"]+)"$', script, flags=re.MULTILINE
        )
        assert len(matches) == 1, f"{name} must have one canonical value"
        return matches[0]

    rules_commit = script_constant("RULES_COMMIT")
    rules_version = script_constant("RULES_VERSION")
    manifest_hash = script_constant("MANIFEST_SHA256")
    assert len(manifest_hash) == 64
    assert f"$r.source_commit -ne '{rules_commit}'" in workflow
    assert f"$r.rules_version -ne '{rules_version}'" in workflow
    assert "python3 scripts/noteri_gateway_refresh.py `" in workflow
    for argument in [
        "--workflow-repository $env:GITHUB_REPOSITORY",
        "--workflow-sha $env:GITHUB_SHA",
        "--workflow-run-id $env:GITHUB_RUN_ID",
        "--workflow-run-attempt $env:GITHUB_RUN_ATTEMPT",
    ]:
        assert argument in workflow
    assert "refresh-run-receipt.json" in workflow
    assert "NOTERI_GATEWAY_REFRESHED" in workflow
    assert "NOTERI_GATEWAY_ALREADY_CURRENT_VERIFIED" in workflow
    assert "installation_performed_by_run" in workflow
    assert "rollback_manifest_sha256" in workflow
    for field in [
        "host",
        "validation_head",
        "workflow_repository",
        "workflow_sha",
        "workflow_run_id",
        "workflow_run_attempt",
        "files",
        "backup_dir",
    ]:
        assert field in workflow
    for relative in [
        "bin/command_gateway.py",
        "bin/host_health_check.py",
        "bin/session_bootstrap.py",
        "bin/session_preflight.py",
        "bin/session_launcher.py",
        "bin/runner_version_preflight.py",
        "config/policy.json",
    ]:
        assert relative in workflow
    assert "Get-FileHash" in workflow
    assert "ShellExecuteW" not in script
    assert "UAC_STARTED_READBACK_REQUIRED" not in script

