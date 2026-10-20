from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "noteri-s3-artifact-profile.yml"


def test_physical_route_is_owner_only_and_never_runs_for_pull_request() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert 'branches:\n      - "feat/noteri-s3-artifact-*"' in raw
    assert "github.actor == 'ericson-j-santos'" in raw
    assert "github.event_name == 'push' || github.event_name == 'workflow_dispatch'" in raw
    assert "runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]" in raw
    assert "pull_request:" in raw
    assert "needs: contract" in raw
    assert "group: noteri-s3-artifact-profile-noteri" in raw
    assert "cancel-in-progress: false" in raw
    assert "timeout-minutes: 8" in raw


def test_workflow_pins_sources_and_disables_checkout_credentials() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "RULES_SHA: a430688c499077f5472841560f224c40766b0b78" in raw
    assert "WORKER_SHA: 5ef413c1c18996bd022c20987fb75dbb9ec47712" in raw
    assert raw.count("persist-credentials: false") == 4
    assert raw.count("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09") == 4
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in raw
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in raw
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093" in raw
    assert "actions/checkout@v" not in raw


def test_workflow_uses_governed_entrypoint_and_no_secret_route() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    contract, physical = raw.split("\n  physical:", maxsplit=1)
    assert "Verify transient Gateway and governed host qualification" in raw
    assert "python3 -I -B scripts/noteri_s3_artifact_profile.py launch" in raw
    assert "noteri_s3_artifact_profile.py launch" in raw
    assert "QUALIFY-NOTERI-S3-ARTIFACT-PROFILE" in raw
    assert "verify-gateway-contract --rules-root _rules" in raw
    assert "build-gateway-bundle" in contract
    assert "noteri-gateway-bundle-${{ github.run_id }}-${{ github.run_attempt }}" in raw
    assert "gateway_bundle_name: ${{ steps.bundle_identity.outputs.name }}" in contract
    assert "gateway_bundle_attempt: ${{ steps.bundle_identity.outputs.attempt }}" in contract
    assert "name: ${{ needs.contract.outputs.gateway_bundle_name }}" in physical
    assert "repository: ericson-j-santos/chatgpt-operational-rules" in contract
    assert "repository: ericson-j-santos/chatgpt-operational-rules" not in physical
    assert physical.count("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09") == 1
    assert physical.count("persist-credentials: false") == 1
    assert "--gateway-root _gateway_bundle" in physical
    assert '--bundle-run-attempt "${{ needs.contract.outputs.gateway_bundle_attempt }}"' in physical
    assert "--rules-root _rules `" not in raw
    assert "secrets." not in raw
    assert "AWS_ACCESS_KEY" not in raw
    assert "AWS_SECRET" not in raw
    assert "Remote Desktop" not in raw
