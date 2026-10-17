import re
from pathlib import Path


def test_gateway_refresh_has_narrow_push_trigger():
    p = Path(__file__).resolve().parents[1] / ".github/workflows/noteri-command-gateway-refresh.yml"
    text = p.read_text(encoding="utf-8")
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
        matches = re.findall(rf'^{name}="([^"]+)"$', script, flags=re.MULTILINE)
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
        "python3 scripts/noteri_gateway_refresh.py --confirm " + confirmation
        in workflow
    )
    assert r"C:\dev\chatgpt-command-gateway\update-receipt.json" in workflow
