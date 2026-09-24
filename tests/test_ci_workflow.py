from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
CHECKOUT_SHA = "fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"


def test_ci_binds_tests_to_exact_head_and_immutable_actions() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    assert "EVALUATED_SHA:" in raw
    assert "github.event.pull_request.head.sha" in raw
    assert f"actions/checkout@{CHECKOUT_SHA}" in raw
    assert f"actions/setup-python@{SETUP_PYTHON_SHA}" in raw
    assert "ref: ${{ env.EVALUATED_SHA }}" in raw
    assert "persist-credentials: false" in raw
    assert 'observed="$(git rev-parse HEAD)"' in raw
    assert 'test "$observed" = "$EVALUATED_SHA"' in raw
    assert "actions/checkout@v4" not in raw
    assert "actions/setup-python@v5" not in raw
