"""Static fail-closed workflow regression for Noteri PostgreSQL qualification."""
from pathlib import Path

WF=Path(__file__).resolve().parents[1]/".github/workflows/noteri-pg18-readonly.yml"

def test_one_use_owner_and_existing_main_sha():
    s=WF.read_text("utf-8")
    assert "OWNER_NOTERI_PG18_READONLY_R2_20261025_ONCE" in s
    assert "OWNER_NOTERI_PG18_READONLY_20261025_ONCE" not in s
    assert "github.event.changes.body.from" in s
    assert "pr.data.base.sha!==main.data.commit.sha" in s
    assert "PG_NOTERI_REAL_CI_REQUIRED" in s
    assert "needs.admission.result == 'success'" in s

def test_safe_nonsecret_error_classification_and_gateway():
    s=WF.read_text("utf-8")
    for key in ("result","source","rules","correlation","ready","db","config",
                "external","docker","packages","services"):
        assert key+"=(" in s
    assert "PG_READBACK_FIELD_RESULTS=" in s
    assert "'--risk','1'" in s
    assert "'--require-runner-version-preflight'" in s
    assert "r.ready_for_pr -ceq $false" in s
    assert "github.rest.actions.listJobsForWorkflowRun" in s
    for forbidden in ("contents: write","neon.tech","docker run","ollama run",
                      "StartService(","CREATE DATABASE"):
        assert forbidden not in s
