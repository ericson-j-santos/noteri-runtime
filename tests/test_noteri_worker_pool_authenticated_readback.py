"""Fixed-path attestation: secrets are read only after verified task identity."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_authenticated_readback as probe
from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_activation as activation

ORIGIN = "https://github.com/ericson-j-santos/engineering-worker-pool"
TOKEN = "a-safe-synthetic-token-that-is-never-printed"


class SecureFixture:
    def __init__(self):
        self.opened = False

    def open_private_read(self, path):
        self.opened = True
        return os.open(path, os.O_RDONLY)

    def validate_private_fd(self, fd):
        assert fd >= 0

    def path_matches_fd(self, fd, path, *, private):
        assert private is True
        return True


def prepare(tmp_path, monkeypatch):
    local = tmp_path
    source = local / "ReqSys" / "NoteriRuntimeRunner" / "_work" / "noteri-runtime" / "noteri-runtime" / "_worker_pool"
    for p in ("app", "contracts/v1"):
        (source / p).mkdir(parents=True)
    (source / "requirements.txt").write_text("fastapi==0.1.0", encoding="utf-8")
    (source / "app" / "__init__.py").write_text("", encoding="utf-8")
    (source / "app" / "main.py").write_text("print('fixture')", encoding="utf-8")
    (source / "app" / "secure_file.py").write_text("VALUE=1", encoding="utf-8")
    for i in range(33):
        (source / "app" / f"module_{i:02d}.py").write_text(f"VALUE={i}", encoding="utf-8")
    (source / "contracts/v1" / "contract.json").write_text("{}", encoding="utf-8")
    assert len(stage.safe_source_files(source)) == 38
    monkeypatch.setattr(stage, "git_identity", lambda _: (probe.SOURCE_SHA, ORIGIN, ""))
    releases = local / reference.RELEASES_RELATIVE
    done = stage.stage(source=source, releases=releases,
                       expected_sha=probe.SOURCE_SHA, profile="NORMAL",
                       hostname="Noteri", platform="nt",
                       inspect_git=lambda _: (probe.SOURCE_SHA, ORIGIN, ""),
                       dry_run=False)
    assert done["result"] == "STAGED_ONLY"
    release = releases / probe.SOURCE_SHA
    cache = release / "app/__pycache__/secure_file.cpython-314.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"synthetic-cache")
    profile = local / reference.PROFILE_RELATIVE
    profile.parent.mkdir(parents=True)
    profile.write_text('{"profile":"NORMAL"}', encoding="utf-8")
    runtime_root = local / "ReqSys" / "NoteriWorkerPool"
    bin_dir = runtime_root / "bin"
    bin_dir.mkdir(parents=True)
    scripts = Path(probe.__file__).parent
    for name in activation.RUNNER_FILES:
        (bin_dir / name).write_bytes((scripts / name).read_bytes())
    venv_python = runtime_root / "venvs" / probe.SOURCE_SHA / "Scripts" / "python.exe"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_bytes(b"fake-runner-executable")
    token_file = local / reference.TOKEN_RELATIVE
    token_file.parent.mkdir()
    token_file.write_text(TOKEN, encoding="utf-8")
    secure = SecureFixture()
    monkeypatch.setattr(reference, "_load_secure_file", lambda *_: secure)
    monkeypatch.setattr(activation, "schtasks", lambda *_: subprocess.CompletedProcess([], 0, stdout=b"safe-fixture"))
    monkeypatch.setattr(activation, "task_matches", lambda *_: True)
    monkeypatch.setattr(probe.control, "verify", lambda *_: True)
    monkeypatch.setattr(activation, "task_com_mismatches", lambda *_: [])
    monkeypatch.setattr(activation, "listener_owned_by_task", lambda *_: True)
    def endpoint(path, bearer=None):
        if path == "/health":
            return 200, {"service": "codex-worker-pool", "status": "healthy",
                         "auth_configured": True,
                         "expected_rules_sha_configured": True, "contract_version": "v1"}
        if bearer == "invalid-attestation-control":
            return 401, None
        if bearer == TOKEN:
            return 200, {"contract_name": "engineering-worker-pool", "contract_version": "v1"}
        return 401, None
    monkeypatch.setattr(activation, "http_status", endpoint)
    return local, secure, cache, token_file


def run(local):
    return probe.attest(local=local, host="Noteri", platform="nt", user="erics")


def test_authenticated_task_bound_contract_and_replay_are_true(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    before = cache.read_bytes()
    result = run(local)
    assert result["result"] == "AUTHENTICATED_READBACK_OK"
    assert result["task_s4u_verified"] is True
    assert result["listener_attributed"] is True
    assert result["negative_auth_verified"] is True
    assert result["contract_authenticated"] is True
    assert result["contract_replay_verified"] is True
    assert result["token_bytes_read"] is True
    assert result["token_disclosed"] is False
    assert result["state_changed"] is False
    assert secure.opened is True
    assert TOKEN not in json.dumps(result)
    assert str(token) not in json.dumps(result)
    assert before == cache.read_bytes()


@pytest.mark.parametrize("denial,method", [
    ("BLOCKED_TASK_XML", "task_matches"),
    ("BLOCKED_TASK_COM", "task_com_mismatches"),
    ("BLOCKED_PROCESS_ATTRIBUTION", "listener_owned_by_task"),
])
def test_no_token_open_when_task_or_listener_not_verified(tmp_path, monkeypatch,
                                                          denial, method):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    if method == "task_matches":
        monkeypatch.setattr(activation, method, lambda *_: False)
    elif method == "task_com_mismatches":
        monkeypatch.setattr(activation, method, lambda *_: ["action_path"])
    else:
        monkeypatch.setattr(activation, method, lambda *_: False)
    result = run(local)
    assert result["result"] == denial
    assert result["token_bytes_read"] is False
    assert secure.opened is False
    assert cache.is_file()


def test_invalid_negative_auth_does_not_open_protected_file(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(activation, "http_status", lambda p, bearer=None:
        (200, {"service": "codex-worker-pool", "status": "healthy",
               "auth_configured": True, "expected_rules_sha_configured": True,
               "contract_version": "v1"}) if p == "/health" else (200, {}))
    result = run(local)
    assert result["result"] == "BLOCKED_NEGATIVE_AUTH"
    assert secure.opened is False


def test_bad_release_cache_or_official_hash_never_reads_token(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    (cache.parent / "unknown.py").write_text("unexpected", encoding="utf-8")
    result = run(local)
    assert result["result"] == "BLOCKED_RELEASE"
    assert secure.opened is False


def test_wrong_host_refused_before_token(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    result = probe.attest(local=local, host="Desktop", platform="nt", user="erics")
    assert result["result"] == "BLOCKED_HOST"
    assert secure.opened is False


def test_wrong_contract_is_not_authenticated_success(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    ok = activation.http_status
    def wrong_contract(path, bearer=None):
        code, data = ok(path, bearer)
        if path == "/v1/contract" and bearer == TOKEN:
            return 200, {"contract_name": "other", "contract_version": "v1"}
        return code, data
    monkeypatch.setattr(activation, "http_status", wrong_contract)
    result = run(local)
    assert result["result"] == "BLOCKED_AUTH_CONTRACT"
    assert result["contract_authenticated"] is False
    assert TOKEN not in json.dumps(result)


def test_probe_has_no_cli_token_or_arbitrary_urls():
    text = (Path(__file__).parents[1] / "scripts" /
            "noteri_worker_pool_authenticated_readback.py").read_text(encoding="utf-8")
    assert "argparse" not in text
    assert "sys.argv" not in text
    assert "subprocess.run" not in text
    assert ".write_text(" not in text
    assert ".unlink(" not in text
    assert "/v1/contract" in text
    assert "invalid-attestation-control" in text


def test_task_com_mismatch_outputs_only_allowlisted_field_names(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(activation, "task_com_mismatches",
                        lambda *_: ["action_path", "principal", "private://do-not-log"])
    result = run(local)
    assert result["result"] == "BLOCKED_TASK_COM"
    assert result["task_difference_fields"] == ["action_path", "other", "principal"]
    assert secure.opened is False
    assert result["token_bytes_read"] is False
    assert "private://do-not-log" not in json.dumps(result)


def test_xml_mismatch_with_matching_com_still_blocks_secret(tmp_path, monkeypatch):
    local, secure, cache, token = prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(activation, "task_matches", lambda *_: False)
    result = run(local)
    assert result["result"] == "BLOCKED_TASK_XML"
    assert result["task_com_verified"] is True
    assert secure.opened is False


def test_xml_difference_fields_never_exposes_task_values(tmp_path):
    python = tmp_path / "python.exe"
    runner = tmp_path / "noteri_worker_pool_api_runner.py"
    principal = "Noteri\\synthetic-user"
    xml = activation.task_xml(python, runner, principal)
    assert probe.xml_difference_fields(xml, python, runner, principal) == []
    changed = xml.replace(b"S4U", b"InteractiveToken")
    assert probe.xml_difference_fields(changed, python, runner, principal) == ["logon_type"]
    sensitive = changed.replace(b"Noteri\\synthetic-user", b"Noteri\\secret-account")
    labels = probe.xml_difference_fields(sensitive, python, runner, principal)
    assert "principal" in labels
    assert "secret-account" not in json.dumps(labels)


def test_unparseable_xml_only_emits_generic_classification(tmp_path):
    assert probe.xml_difference_fields(
        b"\x00bad-private-name\x00", tmp_path / "python.exe",
        tmp_path / "runner.py", "Noteri\\user") == ["xml_parse"]


def test_xml_optional_states_distinguish_missing_and_explicit_conflicts(tmp_path):
    python = tmp_path / "python.exe"
    runner = tmp_path / "runner.py"
    xml = activation.task_xml(python, runner, "Noteri\\synthetic")
    labels = ["boot_trigger", "run_level", "task_enabled"]
    states = probe.xml_optional_field_states(xml, labels)
    assert states == {key: "different" for key in labels}
    # Missing an element differs from an explicit, conflicting value.  No
    # private values are returned, even for malformed/unknown XML content.
    for part in (b"<RunLevel>LeastPrivilege</RunLevel>",
                 b"<Enabled>true</Enabled>"):
        if part in xml:
            altered = xml.replace(part, b"", 1)
            observed = probe.xml_optional_field_states(altered, labels)
            assert "missing" in observed.values()
