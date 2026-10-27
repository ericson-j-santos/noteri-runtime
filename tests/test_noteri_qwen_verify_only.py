"""Contract/negative tests for the Noteri existing-Qwen 7B verification gate.

Fixtures are NOT proof of a physical Ollama run. Only the separately hosted
admission, physical Gateway and independent GitHub readback can prove that.
"""
from __future__ import annotations

from pathlib import Path
import importlib.util

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/noteri-qwen7b-verify-only.yml"
CI = ROOT / ".github/workflows/ci.yml"
SCRIPT = ROOT / "scripts/issue8_native_rag_preflight.py"
RULES_SHA = "d6af41001bf641727a35a990e7c93b4c757538cb"
SCRIPT_SHA = "7135c0fdef65ddf0a7ef637090d18e697453260b"
MARKER = "OWNER_NOTERI_QWEN7B_20261026_READONLY_ONCE"
MODEL_DIGEST = "dae161e27b0e" + "f" * 52


class NoDuplicateKeys(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, val_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate workflow mapping key")
            result[key] = self.construct_object(val_node, deep=deep)
        return result


def parse_workflow(content):
    return yaml.load(content, Loader=NoDuplicateKeys)


def assert_contract(content):
    data = parse_workflow(content)
    assert set(data["jobs"]) == {
        "contract", "admission", "physical",
        "pickup_watchdog", "independent_readback",
    }
    assert data["jobs"]["physical"]["needs"] == "admission"
    assert data["jobs"]["independent_readback"]["needs"] == [
        "admission", "physical",
    ]
    assert "types: [opened, synchronize, edited]" in content
    assert "github.actor == 'ericson-j-santos'" in content
    assert "github.event.changes.body.from != null" in content
    assert f"!contains(github.event.changes.body.from, '{MARKER}')" in content
    assert content.count(MARKER) >= 3
    assert "github.event.pull_request.draft == true" in content
    assert "'feat/noteri-qwen7b-verify-only-20261026'" in content
    assert "NOTERI_MODEL_READONLY_ADMISSION_BLOCKED" in content
    assert "files.data.length!==3" in content
    assert "wanted.get(f.filename)===f.status" in content
    assert "['.github/workflows/noteri-qwen7b-verify-only.yml','added']" in content
    assert "['tests/test_noteri_qwen_verify_only.py','added']" in content
    assert "['.github/workflows/ci.yml','modified']" in content
    assert "c.conclusion==='success'" in content
    assert "source.data.sha!=='" + SCRIPT_SHA + "'" in content
    assert data["jobs"]["physical"]["env"]["RULES_SHA"] == RULES_SHA
    for job_name in ("admission", "independent_readback"):
        scripts = [
            step.get("with", {}).get("script", "")
            for step in data["jobs"][job_name]["steps"]
        ]
        assert any(
            f"rules.data.commit.sha!=='{RULES_SHA}'" in script
            for script in scripts
        )
    assert "ref: ${{ env.EXPECTED_NOTERI_SHA }}" in content
    assert "ref: ${{ env.RULES_SHA }}" in content
    checkouts = [
        step
        for job in data["jobs"].values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("actions/checkout@")
    ]
    assert checkouts
    assert all(
        step.get("with", {}).get("persist-credentials") is False
        for step in checkouts
    )
    assert "self-hosted, Windows, X64, noteri, reqsys-dev" in content
    assert "Noteri-runtime" in content
    assert "runner_id!==21" in content or "j.runner_id===21" in content
    assert "--require-runner-version-preflight" in content
    assert "SESSION_LAUNCH_OK" in content
    assert "command_gateway.py" in content
    assert "'--risk','1'" in content and "'--timeout','120'" in content
    assert "--verify-ollama-qwen7b" in content
    assert "--install-ollama-qwen7b" not in content
    assert "NOTERI_QWEN7B_MODEL_READONLY_VERIFIED" in content
    assert "NOTERI_EXISTING_QWEN7B_PHYSICAL_VERIFIED" in content
    assert "MODEL_DIGEST_PREFIX!=='dae161e27b0e'" in content
    assert "model_state_changed -ne $false" in content
    assert "git_state_changed -ne $false" in content
    assert "NOTERI_MODEL_SANITIZED_FAILURE=" in content
    assert "limit=300000" in content and "cancelWorkflowRun" in content
    assert "steps.every(name=>" in content
    assert "needs: [admission, physical]" in content
    assert "actions/upload-artifact" not in content
    assert "actions/download-artifact" not in content
    assert "docker " not in content.lower()
    assert "ollama pull" not in content.lower()
    assert "force-push" not in content.lower()
    assert "sudo " not in content.lower()
    assert "secrets." not in content
    assert "contents: write" not in content


def local_model_module():
    spec = importlib.util.spec_from_file_location(
        "noteri_existing_qwen_test", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_verify_only_workflow_complete_and_strict():
    assert_contract(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize(("original", "replacement"), [
    ("types: [opened, synchronize, edited]", "types: [opened, synchronize]"),
    ("--require-runner-version-preflight", "--unsafe-disabled"),
    ("--verify-ollama-qwen7b", "--unsafe-disabled"),
    ("NOTERI_MODEL_READONLY_ADMISSION_BLOCKED", "UNSAFE_DISABLED"),
    ("c.conclusion==='success'", "c.conclusion!=='success'"),
    ("persist-credentials: false", "persist-credentials: true"),
    ("NOTERI_MODEL_SANITIZED_FAILURE=", "UNSAFE_DISABLED="),
    ("steps.every(name=>", "steps.some(name=>"),
    ("limit=300000", "limit=3600000"),
    ("files.data.length!==3", "files.data.length!==2"),
    ("wanted.get(f.filename)===f.status", "wanted.has(f.filename)"),
    ("['.github/workflows/ci.yml','modified']",
     "['.github/workflows/ci.yml','added']"),
    (RULES_SHA, "0" * 40),
])
def test_required_gate_removed_is_detected(original, replacement):
    y = WORKFLOW.read_text(encoding="utf-8")
    assert original in y
    mutated = y.replace(original, replacement, 1)
    # A parser error must not masquerade as rejection of an unsafe setting.
    parse_workflow(mutated)
    with pytest.raises(AssertionError):
        assert_contract(mutated)


def assert_ci_dependencies(content):
    data = parse_workflow(content)
    installs = [
        step.get("run", "")
        for step in data["jobs"]["tests"]["steps"]
        if step.get("name") == "Install test dependencies"
    ]
    assert len(installs) == 1
    arguments = installs[0].split()
    assert "pytest==8.4.2" in arguments
    assert "PyYAML==6.0.2" in arguments


def test_main_ci_installs_contract_dependencies():
    assert_ci_dependencies(CI.read_text(encoding="utf-8"))


@pytest.mark.parametrize("dependency", ["pytest==8.4.2", "PyYAML==6.0.2"])
def test_ci_dependency_removed_is_detected(dependency):
    content = CI.read_text(encoding="utf-8")
    assert dependency in content
    mutated = content.replace(dependency, "", 1)
    parse_workflow(mutated)
    with pytest.raises(AssertionError):
        assert_ci_dependencies(mutated)


def test_parser_refuses_duplicate_key_and_malformed_yaml():
    y = WORKFLOW.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate workflow mapping key"):
        parse_workflow(y + "\njobs:\n  rogue: {}\n")
    with pytest.raises(yaml.YAMLError):
        parse_workflow(y + "\nunclosed: [invalid\n")


def test_verify_mode_does_not_pull_even_when_missing(monkeypatch):
    m = local_model_module()
    calls = []

    def store():
        calls.append("store")
        return {"qwen_tag_present": True, "model_store_bound_to_daemon": True}

    def verified():
        calls.append("model")
        return {"digest": MODEL_DIGEST, "size": 4683074048}

    def forbid_pull():
        raise AssertionError("verify-only must never download a model")

    monkeypatch.setattr(m, "inspect_ollama_model_store", store)
    monkeypatch.setattr(m, "_verify_local_qwen7b", verified)
    monkeypatch.setattr(m, "_pull_exact_ollama_model", forbid_pull)

    result = m.provision_ollama_qwen7b("verify")
    assert result == {
        "result": "ISSUE8_OLLAMA_QWEN7B_VERIFIED",
        "mode": "verify", "model_name": "qwen2.5-coder:7b",
        "digest": MODEL_DIGEST, "size": 4683074048,
        "model_state_changed": False, "git_state_changed": False,
    }
    assert calls == ["store", "model", "store"]

    monkeypatch.setattr(m, "inspect_ollama_model_store", lambda: {
        "qwen_tag_present": False, "model_store_bound_to_daemon": True
    })
    with pytest.raises(m.PreflightBlocked, match="issue8_model_final_readback_invalid"):
        m.provision_ollama_qwen7b("verify")


def test_wrong_digest_aborts_and_preserves_no_pull(monkeypatch):
    m = local_model_module()
    monkeypatch.setattr(m, "inspect_ollama_model_store", lambda: {
        "qwen_tag_present": True, "model_store_bound_to_daemon": True
    })
    def fail():
        raise m.PreflightBlocked("issue8_model_digest_mismatch")
    monkeypatch.setattr(m, "_verify_local_qwen7b", fail)
    monkeypatch.setattr(m, "_pull_exact_ollama_model",
                        lambda: pytest.fail("unexpected model download"))
    with pytest.raises(m.PreflightBlocked, match="issue8_model_digest_mismatch"):
        m.provision_ollama_qwen7b("verify")


def test_existing_script_limits_to_loopback_and_keeps_memory_gate():
    s = SCRIPT.read_text(encoding="utf-8")
    assert "http://127.0.0.1:11434/api/tags" in s
    assert "require_qwen_memory_headroom()" in s
    assert 'if mode == "install" and not before["qwen_tag_present"]:' in s
    assert "--verify-ollama-qwen7b" in s
    assert "10 * 1024 ** 3" in s
    assert "issue8_model_storage_not_attested" in s
