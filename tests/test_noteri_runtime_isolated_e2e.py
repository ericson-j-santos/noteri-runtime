from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "noteri_runtime_isolated_e2e.py"
SPEC = importlib.util.spec_from_file_location("noteri_runtime_isolated_e2e", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_validate_inputs_accepts_exact_noteri_contract() -> None:
    module.validate_inputs(
        host="Noteri",
        expected_sha="a" * 40,
        correlation_id="corr-noteri-runtime-001",
    )


@pytest.mark.parametrize(
    ("host", "sha", "correlation"),
    [
        ("other-host", "a" * 40, "corr-noteri-runtime-001"),
        ("Noteri", "invalid", "corr-noteri-runtime-001"),
        ("Noteri", "a" * 40, "short"),
    ],
)
def test_validate_inputs_fails_closed(host: str, sha: str, correlation: str) -> None:
    with pytest.raises((RuntimeError, ValueError)):
        module.validate_inputs(host=host, expected_sha=sha, correlation_id=correlation)



class _CompletedGit:
    returncode = 0
    stdout = "a" * 40 + "\n"


class _FailedGit:
    returncode = 1
    stdout = ""


def test_resolve_source_sha_reads_exact_git_head(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: _CompletedGit())
    assert module.resolve_source_sha(tmp_path) == "a" * 40


def test_resolve_source_sha_fails_closed_when_git_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: _FailedGit())
    with pytest.raises(RuntimeError, match="source_sha_unavailable"):
        module.resolve_source_sha(tmp_path)


def test_resolve_source_sha_rejects_invalid_git_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class InvalidGit:
        returncode = 0
        stdout = "not-a-sha\n"

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: InvalidGit())
    with pytest.raises(RuntimeError, match="source_sha_invalid"):
        module.resolve_source_sha(tmp_path)

def test_validate_independent_state_requires_transition_replay_and_negative_control(tmp_path: Path) -> None:
    profile = tmp_path / "host-profile.json"
    audit = tmp_path / "host-profile-audit.jsonl"
    profile.write_text(
        json.dumps({"profile": "NORMAL", "accepts_new_development": True}) + "\n",
        encoding="utf-8",
    )
    prefix = "corr-noteri-runtime-001"
    audit_rows = [
        {"correlation_id": prefix + "-123-estudo", "after_profile": "ESTUDO", "changed": True},
        {"correlation_id": prefix + "-123-normal", "after_profile": "NORMAL", "changed": True},
        {"correlation_id": prefix + "-123-normal-repeat", "after_profile": "NORMAL", "changed": False},
    ]
    audit.write_text(
        "".join(json.dumps(row) + "\n" for row in audit_rows),
        encoding="utf-8",
    )
    result = module.validate_independent_state(
        profile_path=profile,
        audit_path=audit,
        correlation_id=prefix,
        e2e={
            "negative_control": {
                "http_status": 409,
                "error": "host_target_mismatch",
            }
        },
    )
    assert result["profile"] == "NORMAL"
    assert result["idempotent_replay"] is True
    assert result["negative_control"] is True


def test_validate_independent_state_rejects_non_normal_final_state(tmp_path: Path) -> None:
    profile = tmp_path / "host-profile.json"
    audit = tmp_path / "host-profile-audit.jsonl"
    profile.write_text(
        json.dumps({"profile": "ESTUDO", "accepts_new_development": False}) + "\n",
        encoding="utf-8",
    )
    audit.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="final_profile_not_normal"):
        module.validate_independent_state(
            profile_path=profile,
            audit_path=audit,
            correlation_id="corr-noteri-runtime-001",
            e2e={"negative_control": {"http_status": 409, "error": "host_target_mismatch"}},
        )
