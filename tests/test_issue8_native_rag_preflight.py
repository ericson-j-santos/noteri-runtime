"""Issue8 Noteri physical RAG preflight: fail-closed, no side effects.

Live GitHub admission/Ollama are deliberately NOT faked into acceptance.
These are contract fixtures; the physical workflow must prove actual calls.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "issue8_native_rag_preflight.py"
WORKFLOW = ROOT / ".github/workflows/issue8-qwen-native-rag-readonly.yml"


def module():
    s=importlib.util.spec_from_file_location("issue8_native_rag_preflight",SCRIPT)
    assert s is not None and s.loader is not None
    x=importlib.util.module_from_spec(s)
    sys.modules[s.name]=x
    s.loader.exec_module(x)
    return x


def valid_env(m, workspace):
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": m.HOST_REPOSITORY,
        "RUNNER_NAME": "Noteri-runtime",
        "NATIVE_OLLAMA_DEV": "1",
        "NATIVE_MODEL_DIGEST_PREFIX": m.MODEL_PIN,
        "SESSION_LAUNCH_RESULT": "SESSION_LAUNCH_OK",
        "SESSION_STATE_VALIDATED": "true",
        "SESSION_GATEWAY_BOUND": "true",
        "SESSION_ID": "issue8-noteri-test-1",
        "SESSION_SNAPSHOT_SHA256": "a"*64,
        "CORRELATION_ID": "issue8-noteri-12345-1",
        "EXPECTED_NOTERI_SHA": "b"*40,
        "WORKER_POOL_SHA": m.WORKER_SHA,
        "RULES_SHA": m.RULES_SHA,
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKSPACE": str(workspace),
        "SESSION_TARGET_PATH": str(workspace / "session"),
    }


@pytest.mark.parametrize("inventory,expected", [
    ([], "issue8_model_inventory_invalid"),
    ([{"name": "unrelated", "digest": "a" * 64}],
     "issue8_model_tag_missing"),
    ([{"name": "qwen2.5-coder:latest",
       "digest": "dae161e27b0e" + "a" * 52}],
     "issue8_model_pinned_under_other_tag"),
    ([{"name": "qwen2.5-coder:7b"}] * 2,
     "issue8_model_tag_duplicate"),
    ([{"name": "qwen2.5-coder:7b", "digest": "b" * 64}],
     "tag_present"),
])
def test_native_model_inventory_reason_is_bounded_and_readonly(inventory, expected):
    m = module()
    if expected == "tag_present":
        assert m.inspect_native_model_inventory(
            inventory, "qwen2.5-coder:7b", m.MODEL_PIN
        ) == "tag_present"
    else:
        with pytest.raises(m.PreflightBlocked, match="^" + expected + "$"):
            m.inspect_native_model_inventory(
                inventory, "qwen2.5-coder:7b", m.MODEL_PIN
            )
    assert "secret" not in expected


def test_native_model_preflight_is_before_research_and_does_not_bypass_attestation():
    script = SCRIPT.read_text(encoding="utf-8")
    assert script.index("probe_native_model()\n    _set_phase('research')") > script.index(
        "_set_phase('model')"
    )
    assert 'NativeStructuredOllama.select_model(models)' in script
    assert 'LocalOllama.request(client, "GET", "/api/tags")' in script
    assert "trust_env=False, follow_redirects=False" in script
    assert "ollama pull" not in script.lower()
    assert "ollama cp" not in script.lower()

def test_positive_host_identity_does_not_authorize_execution(tmp_path):
    m=module()
    a=m.validate_environment(valid_env(m,tmp_path))
    assert a["runtime_sha"]=="b"*40
    assert a["run_id"]=="12345"
    assert m.MODEL_PIN=="dae161e27b0e"
    assert m.WORKER_SHA=="047c77b6b867ff5d489bd74f6fd80989719ab85e"
    assert m.OWNER_COMMENT_ID==6423646539


@pytest.mark.parametrize("field,value",[
    ("GITHUB_ACTIONS","false"),
    ("GITHUB_REPOSITORY","untrusted/repo"),
    ("RUNNER_NAME","Noteri-legacy"),
    ("NATIVE_OLLAMA_DEV","0"),
    ("NATIVE_MODEL_DIGEST_PREFIX",""),
    ("SESSION_LAUNCH_RESULT","DIAGNOSTIC_OK"),
    ("SESSION_STATE_VALIDATED","false"),
    ("SESSION_GATEWAY_BOUND","false"),
    ("SESSION_ID","bad session"),
    ("SESSION_SNAPSHOT_SHA256","x"*64),
    ("CORRELATION_ID","bad; injection"),
    ("EXPECTED_NOTERI_SHA","abc"),
    ("WORKER_POOL_SHA","c"*40),
    ("RULES_SHA","c"*40),
    ("GITHUB_RUN_ID","unsafe"),
    ("GITHUB_RUN_ATTEMPT","0"),
    ("GITHUB_WORKSPACE",""),
])
def test_host_or_owner_context_fail_before_inference(tmp_path,field,value,monkeypatch):
    m=module()
    env=valid_env(m,tmp_path)
    env[field]=value
    called=[]
    monkeypatch.setattr(m,"verify_pinned_checkout",lambda *_: called.append(True))
    with pytest.raises(m.PreflightBlocked):
        m.run(env)
    assert not called


def test_read_only_git_whitelist(monkeypatch,tmp_path):
    m=module()
    seen=[]
    def execute(cmd,**kw):
        seen.append(cmd)
        assert cmd[:1]==["git"] and cmd[1:] in (
            ["rev-parse","HEAD"],
            ["status","--porcelain","--untracked-files=no"],
        )
        assert kw["env"]["GIT_TERMINAL_PROMPT"]=="0"
        assert kw["env"]["GIT_OPTIONAL_LOCKS"]=="0"
        assert kw["check"] is False
        return subprocess.CompletedProcess(cmd,0,"a"*40+"\n","")
    monkeypatch.setattr(m.subprocess,"run",execute)
    assert m.read_git(tmp_path,"rev-parse","HEAD")=="a"*40
    with pytest.raises(m.PreflightBlocked,match="issue8_git_action_not_allowlisted"):
        m.read_git(tmp_path,"push","--force")
    assert seen==[["git","rev-parse","HEAD"]]


def test_git_error_is_sanitized(monkeypatch,tmp_path):
    m=module()
    monkeypatch.setattr(m.subprocess,"run",lambda *a,**k:
                        subprocess.CompletedProcess(a,128,"","TOKEN=SENSITIVE"))
    with pytest.raises(m.PreflightBlocked,match="^issue8_git_sha_invalid$") as x:
        m.read_git(tmp_path,"rev-parse","HEAD")
    assert "SENSITIVE" not in str(x.value)


def test_source_blob_revalidated_before_any_model(monkeypatch,tmp_path):
    m=module()
    env=valid_env(m,tmp_path)
    workspace=tmp_path
    (workspace/"session"/"scripts").mkdir(parents=True)
    (workspace/"session"/"scripts"/"issue8_native_rag_preflight.py").write_text("pass\n")
    (workspace/"_worker_pool"/"app").mkdir(parents=True)
    (workspace/"_rules").mkdir()
    content=b"from source at pinned SHA\n"
    (workspace/"_worker_pool"/m.SOURCE_PATH).write_bytes(content)
    digest=hashlib.sha1(
        b"blob "+str(len(content)).encode()+b"\0"+content,
    ).hexdigest()
    monkeypatch.setattr(m,"SOURCE_BLOB_SHA",digest)
    monkeypatch.setattr(m,"canonical_git_source",lambda _root: content)
    def get(root,*args):
        if args==("status","--porcelain","--untracked-files=no"):
            return ""
        return (env["EXPECTED_NOTERI_SHA"] if root.name=="session"
                else m.WORKER_SHA if root.name=="_worker_pool" else m.RULES_SHA)
    monkeypatch.setattr(m,"read_git",get)
    identity=m.validate_environment(env)
    worker,raw=m.verify_pinned_checkout(env,identity)
    assert worker.name=="_worker_pool" and raw==content
    (workspace/"_worker_pool"/m.SOURCE_PATH).write_bytes(content+b"tampered")
    with pytest.raises(m.PreflightBlocked,match="issue8_checkout_bytes_drift"):
        m.verify_pinned_checkout(env,identity)


def test_source_get_allows_only_exact_static_paths_and_sha():
    m=module()
    class Reader:
        def get_text_file(self,repo,path,sha):
            payload=b"# independently cited evidence\n"
            sha1=hashlib.sha1(
                b"blob "+str(len(payload)).encode()+b"\0"+payload,
            ).hexdigest()
            return {
                "type":"file","path":path,"encoding":"base64",
                "size":len(payload),"content":base64.b64encode(payload).decode(),
                "sha":sha1,
            }
    r=Reader()
    assert m.read_original_bytes(r,"README.md",m.WORKER_SHA).startswith(b"#")
    for path in ("app/portfolio_bridge.py","docs/private.md","../secrets.md"):
        with pytest.raises(m.PreflightBlocked,match="issue8_independent_path_invalid"):
            m.read_original_bytes(r,path,m.WORKER_SHA)
    with pytest.raises(m.PreflightBlocked,match="issue8_independent_path_invalid"):
        m.read_original_bytes(r,"README.md","0"*40)


def test_nonzero_on_unknown_exception_avoids_secret_leak(monkeypatch,capsys):
    m=module()
    monkeypatch.setattr(m,"run",lambda *_: (_ for _ in ()).throw(
        RuntimeError("secret bearer token")))
    assert m.main([])==2
    msg=json.loads(capsys.readouterr().out)
    assert msg["result"]=="ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED"
    assert msg["reason_code"]=="issue8_native_dependency_unavailable"
    assert "bearer" not in json.dumps(msg)


def test_workflow_has_gated_one_shot_routing_and_no_write_permissions():
    t=WORKFLOW.read_text(encoding="utf-8")
    assert "types: [edited]" in t
    assert "github.actor == 'ericson-j-santos'" in t
    assert "github.event.changes.body.from != null" in t
    assert "OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261026_POST_MODEL_READY_ONCE" in t
    assert "ISSUE8_SANITIZED_FAILURE=" in t
    assert "^(?:issue8_|rag_|main_|owner_|native_|github_|context_)[a-z0-9_]{2,95}$" in t
    assert "ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED" in t
    assert "gatewayStatus -ne 0" in t
    assert "2>&1" in t
    assert "!contains(github.event.changes.body.from, 'OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261026_POST_MODEL_READY_ONCE')" in t
    assert "throw 'ISSUE8_NATIVE_RAG_GATEWAY_BLOCKED'" in t
    assert "runner_name" in t
    assert "Noteri-runtime" in t
    assert "6423646539" in t
    assert m_sha_in_text(t)
    assert "--require-runner-version-preflight" in t
    assert "SESSION_LAUNCH_OK" in t
    assert "command_gateway.py" in t
    assert "'--risk','1'" in t and "'--risk','2'" in t
    assert "ISSUE8_NATIVE_RAG_PREFLIGHT_VERIFIED" in t
    assert "300000" in t and "cancelWorkflowRun" in t
    assert "sudo " not in t.lower()
    assert "docker " not in t.lower()
    assert "ollama pull" not in t.lower()
    assert "force-push" not in t.lower()
    assert "contents: write" not in t


def m_sha_in_text(t):
    return ("047c77b6b867ff5d489bd74f6fd80989719ab85e" in t
            and "8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8" in t)


def test_issue8_workflow_yaml_parses_with_hosted_runner_runtime(tmp_path):
    """Catch syntactically broken Action files even if source-code tests pass."""
    import shutil
    ruby = shutil.which("ruby")
    assert ruby is not None, "Ubuntu hosted CI must have Ruby/Psych for YAML gate"
    check = subprocess.run(
        [ruby, "-e", "require 'yaml'; Psych.parse_file(ARGV.fetch(0))", str(WORKFLOW)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert check.returncode == 0, check.stderr
    assert WORKFLOW.read_text(encoding="utf-8").rstrip().endswith("}));")
    # Mutation control: the same parser MUST reject the previous failure class.
    negative_file = tmp_path / "invalid_issue8_workflow.yml"
    negative_file.write_text(
        WORKFLOW.read_text(encoding="utf-8") + "\n) {\n", encoding="utf-8",
    )
    negative = subprocess.run(
        [ruby, "-e", "require 'yaml'; Psych.parse_file(ARGV.fetch(0))", str(negative_file)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert negative.returncode != 0, "Parser ignored malformed workflow"


def test_issue8_recovery_gate_is_scope_bound_and_fail_closed():
    content = WORKFLOW.read_text(encoding="utf-8")
    assert "feat/issue8-native-rag-preflight-20261025" not in content
    assert "fix/issue8-native-rag-yaml-gate-20261025" in content
    assert "OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261025_ONCE" not in content
    assert "OWNER_ISSUE8_NATIVE_RAG_NOTERI_20261026_POST_MODEL_READY_ONCE" in content
    assert "ISSUE8_SANITIZED_FAILURE=" in content
    assert "ISSUE8_GATEWAY_ENVELOPE_UNAVAILABLE" in content
    assert "gatewayStatus -ne 0" in content
    assert "2>&1" in content
    assert "'--risk','1'" in content
    assert "d.head.sha!==sha" in content
    assert "github.actor == 'ericson-j-santos'" in content
    assert "'scripts/issue8_native_rag_preflight.py'," in content
    assert "contents: write" not in content


def test_git_blob_uses_binary_sha_bound_object_not_checkout(tmp_path, monkeypatch):
    """A CRLF checkout must not change original Git blob bytes."""
    m = module()
    source = b"# authoritative source\nline two\n"
    sha = hashlib.sha1(
        b"blob " + str(len(source)).encode() + b"\0" + source
    ).hexdigest()
    monkeypatch.setattr(m, "SOURCE_BLOB_SHA", sha)
    calls = []
    def run_git(args, **kwargs):
        calls.append(args)
        assert args == ["git", "show", "HEAD:" + m.SOURCE_PATH]
        assert kwargs["text"] is False
        assert kwargs["check"] is False
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"
        return subprocess.CompletedProcess(args, 0, source, b"")
    monkeypatch.setattr(m.subprocess, "run", run_git)
    assert m.canonical_git_source(tmp_path) == source
    assert calls == [["git", "show", "HEAD:" + m.SOURCE_PATH]]


def test_crlf_checkout_accepted_only_if_exact_normalization(tmp_path, monkeypatch):
    m = module()
    env = valid_env(m, tmp_path)
    (tmp_path / "session" / "scripts").mkdir(parents=True)
    (tmp_path / "session" / "scripts" / "issue8_native_rag_preflight.py").write_text("pass\n")
    worker = tmp_path / "_worker_pool"
    (worker / "app").mkdir(parents=True)
    (tmp_path / "_rules").mkdir()
    canonical = b"line one\nline two\n"
    (worker / m.SOURCE_PATH).write_bytes(canonical.replace(b"\n", b"\r\n"))
    monkeypatch.setattr(m, "canonical_git_source", lambda _: canonical)
    def git(root, *args):
        if args == ("status", "--porcelain", "--untracked-files=no"):
            return ""
        return (env["EXPECTED_NOTERI_SHA"] if root.name == "session"
                else m.WORKER_SHA if root.name == "_worker_pool" else m.RULES_SHA)
    monkeypatch.setattr(m, "read_git", git)
    assert m.verify_pinned_checkout(env, m.validate_environment(env))[1] == canonical
    (worker / m.SOURCE_PATH).write_bytes(b"line one\r\nEVIL\r\n")
    with pytest.raises(m.PreflightBlocked, match="issue8_checkout_bytes_drift"):
        m.verify_pinned_checkout(env, m.validate_environment(env))


def test_unexpected_git_blob_or_stderr_blocks_with_sanitized_reason(tmp_path, monkeypatch):
    m = module()
    source = b"approved\n"
    monkeypatch.setattr(m, "SOURCE_BLOB_SHA", "a" * 40)
    for result, reason in [
        (subprocess.CompletedProcess([], 1, b"", b"secret"), "issue8_git_blob_invalid"),
        (subprocess.CompletedProcess([], 0, source, b""), "issue8_source_blob_drift"),
    ]:
        monkeypatch.setattr(m.subprocess, "run", lambda *args, **kw: result)
        with pytest.raises(m.PreflightBlocked, match="^" + reason + "$") as blocked:
            m.canonical_git_source(tmp_path)
        assert "secret" not in str(blocked.value)


def test_rejected_preflight_identifies_phase_without_secret(monkeypatch, tmp_path, capsys):
    m = module()
    env = valid_env(m, tmp_path)
    def reject(*_):
        raise m.PreflightBlocked("issue8_checkout_bytes_drift")
    monkeypatch.setattr(m, "verify_pinned_checkout", reject)
    monkeypatch.setattr(m.os, "environ", env)
    assert m.main([]) == 2
    value = json.loads(capsys.readouterr().out)
    assert value["reason_code"] == "issue8_checkout_bytes_drift"
    assert value["phase"] == "checkouts"
    assert value["state_changed"] is False


def test_unknown_exception_is_fixed_code_even_with_secret(monkeypatch, tmp_path, capsys):
    m = module()
    env = valid_env(m, tmp_path)
    def reject(*_):
        raise RuntimeError("secret=never-print")
    monkeypatch.setattr(m, "verify_pinned_checkout", reject)
    monkeypatch.setattr(m.os, "environ", env)
    assert m.main([]) == 2
    value = json.loads(capsys.readouterr().out)
    assert value["reason_code"] == "issue8_native_dependency_unavailable"
    assert value["phase"] == "checkouts"
    assert "never-print" not in json.dumps(value)


def test_ollama_store_attestation_requires_real_matching_manifest(tmp_path, monkeypatch):
    import platform
    import socket
    m = module()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(socket, "gethostname", lambda: "Noteri")
    data = b'{"schemaVersion":2,"config":{"digest":"sha256:aaaa"}}'
    digest = hashlib.sha256(data).hexdigest()
    manifest = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "qwen2.5-coder" / "1.5b"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(data)
    class Drive:
        free = 10 * 1024 ** 3
    reader = lambda _: Drive()
    source = [{"name": "qwen2.5-coder:1.5b", "digest": digest}]
    outcome = m.inspect_ollama_model_store(
        model_root=tmp_path, inventory=source, disk_usage=reader
    )
    assert outcome["result"] == "ISSUE8_MODEL_STORAGE_READONLY_VERIFIED"
    assert outcome["manifest_matches"] == 1
    assert outcome["qwen_tag_present"] is False
    assert outcome["state_changed"] is False
    manifest.write_bytes(b"corrupted")
    with pytest.raises(m.PreflightBlocked, match="issue8_model_storage_not_attested"):
        m.inspect_ollama_model_store(model_root=tmp_path, inventory=source, disk_usage=reader)
    manifest.write_bytes(data)
    Drive.free -= 1
    with pytest.raises(m.PreflightBlocked, match="issue8_model_storage_insufficient"):
        m.inspect_ollama_model_store(model_root=tmp_path, inventory=source, disk_usage=reader)


def test_ollama_store_host_and_wrong_digest_control(tmp_path, monkeypatch):
    import platform
    import socket
    m = module()
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(socket, "gethostname", lambda: "Noteri")
    with pytest.raises(m.PreflightBlocked, match="issue8_model_host_unverified"):
        m.inspect_ollama_model_store(model_root=tmp_path, inventory=[])
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    class Drive:
        free = 20 * 1024 ** 3
    with pytest.raises(m.PreflightBlocked, match="issue8_model_digest_mismatch"):
        m.inspect_ollama_model_store(
            model_root=tmp_path,
            inventory=[{"name": "qwen2.5-coder:7b", "digest": "a" * 64}],
            disk_usage=lambda _: Drive(),
        )


def test_ollama_store_opt_in_mode_does_not_change_rag_default(monkeypatch, capsys):
    m = module()
    monkeypatch.setattr(m.sys, "argv", ["preflight", "--inspect-ollama-model-store"])
    monkeypatch.setattr(m, "inspect_ollama_model_store",
                        lambda: {"result": "ISSUE8_MODEL_STORAGE_READONLY_VERIFIED",
                                 "state_changed": False})
    assert m.main() == 0
    assert json.loads(capsys.readouterr().out)["result"] == "ISSUE8_MODEL_STORAGE_READONLY_VERIFIED"
    monkeypatch.setattr(m.sys, "argv", ["preflight", "--install-any-model"])
    assert m.main() == 2
    assert "issue8_cli_mode_invalid" in capsys.readouterr().out
