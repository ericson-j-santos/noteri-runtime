from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "physical-e2e.yml"


def test_physical_e2e_is_manual_exact_sha_and_noteri_only() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in raw
    assert "pull_request:" not in raw
    # O E2E mutavel continua exclusivamente manual. Somente o inventario Risk1
    # da branch exata pode ser disparado uma vez por marcador do proprietario.
    assert "push:\\n    branches: [fix/noteri-watchdog-transactional-upgrade-20261115]" in raw
    assert "if: github.event_name == 'workflow_dispatch' && inputs.mode == 'e2e'" in raw
    assert "github.actor == 'ericson-j-santos'" in raw
    assert "contains(github.event.head_commit.message, '[risk1-inventory-once]')" in raw
    assert "'--risk', '1'" in raw
    assert "installation_authorized -ne $false" in raw
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in raw
    assert "ref: ${{ github.sha }}" in raw
    assert "persist-credentials: false" in raw
    assert "noteri_runtime_isolated_e2e.py" in raw
    assert "final_profile_not_normal" in raw
    assert "idempotency_missing" in raw
    assert "negative_control_missing" in raw
    assert "observed_sha_mismatch" in raw
    assert "source_sha_not_verified" in raw
    assert "rdc_dependency_detected" in raw
    assert "secrets." not in raw
