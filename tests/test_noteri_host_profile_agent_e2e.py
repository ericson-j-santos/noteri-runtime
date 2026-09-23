from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "noteri_host_profile_agent_e2e.py"
SPEC = importlib.util.spec_from_file_location("noteri_host_profile_agent_e2e", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_agent_url_accepts_isolated_port() -> None:
    assert module.agent_url(18765) == "http://127.0.0.1:18765"


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_agent_url_rejects_invalid_port(port: int) -> None:
    with pytest.raises(ValueError, match="1 e 65535"):
        module.agent_url(port)


def test_set_and_verify_propagates_selected_port(monkeypatch) -> None:
    calls: list[tuple[str, int, str]] = []

    def fake_request(path: str, *, port: int, method: str = "GET", body=None):
        calls.append((path, port, method))
        if method == "POST":
            return {"ok": True, "profile": "NORMAL", "accepts_new_development": True, "changed": False}
        return {"ok": True, "profile": "NORMAL", "accepts_new_development": True}

    monkeypatch.setattr(module, "request", fake_request)
    result = module.set_and_verify("NORMAL", "corr-port-test-001", port=18765)

    assert result["observed"]["profile"] == "NORMAL"
    assert calls == [
        ("/v1/profile", 18765, "POST"),
        ("/v1/profile", 18765, "GET"),
    ]
