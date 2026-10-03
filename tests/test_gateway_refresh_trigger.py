from pathlib import Path


def test_gateway_refresh_has_narrow_push_trigger():
    p = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-command-gateway-refresh.yml"
    text = p.read_text(encoding="utf-8")
    assert "  workflow_dispatch:" in text
    assert "  push:" in text
    assert "    branches: [main]" in text
    assert "      - '.github/triggers/noteri-command-gateway-refresh'" in text
    assert "repository_dispatch" not in text
