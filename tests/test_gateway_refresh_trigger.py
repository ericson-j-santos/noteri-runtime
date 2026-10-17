import re
from pathlib import Path


def test_gateway_refresh_has_narrow_push_trigger():
    path = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/noteri-command-gateway-refresh.yml"
    )
    text = path.read_text(encoding="utf-8")
    assert "  workflow_dispatch:" in text
    assert "  push:" in text
    assert "    branches: [main]" in text
    assert "      - '.github/triggers/noteri-command-gateway-refresh'" in text
    assert "repository_dispatch" not in text


def test_gateway_refresh_readback_matches_script_contract():
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github/workflows/noteri-command-gateway-refresh.yml"
    ).read_text(encoding="utf-8")
    script = (
        Path(__file__).resolve().parents[1] / "scripts/noteri_gateway_refresh.py"
    ).read_text(encoding="utf-8")

    def script_constant(name):
        matches = re.findall(
            rf'^{name}\s*=\s*"([^"]+)"$', script, flags=re.MULTILINE
        )
        assert len(matches) == 1, f"{name} must have one canonical value"
        return matches[0]

    def readback_literal(field):
        matches = re.findall(
            re.escape(f"$r.{field}") + r"\s+-ne\s+'([^']+)'", workflow
        )
        assert len(matches) == 1, f"{field} readback must be unique"
        return matches[0]

    rules_commit = script_constant("RULES_COMMIT")
    rules_version = script_constant("RULES_VERSION")
    confirmation = script_constant("CONFIRM")

    assert re.fullmatch(r"[0-9a-f]{40}", rules_commit)
    assert re.fullmatch(r"\d+\.\d+\.\d+", rules_version)
    assert readback_literal("source_commit") == rules_commit
    assert readback_literal("rules_version") == rules_version
    assert (
        "python3 scripts/noteri_gateway_refresh.py `" in workflow
        and "--confirm " + confirmation in workflow
    )
    assert r"C:\dev\chatgpt-command-gateway" in workflow
    for argument in [
        "--workflow-repository $env:GITHUB_REPOSITORY",
        "--workflow-sha $env:GITHUB_SHA",
        "--workflow-run-id $env:GITHUB_RUN_ID",
        "--workflow-run-attempt $env:GITHUB_RUN_ATTEMPT",
    ]:
        assert argument in workflow
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
    assert "rollback-manifest.json" in workflow
    assert "ShellExecuteW" not in script
    assert "UAC_STARTED_READBACK_REQUIRED" not in script
