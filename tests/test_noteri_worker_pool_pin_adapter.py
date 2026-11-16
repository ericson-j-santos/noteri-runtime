"""Target-specific Worker Pool adapter: real Git, synthetic model, no live lease.

These tests exercise the actual pinned shared NativeOneShot data contracts.
They never assert that Qwen ran physically or that a CAS artifact was published.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from app.native_one_shot import AdapterContext, TaskManifest, AdapterResult
from scripts import noteri_worker_pool_pin_adapter as repair

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL = "58dcd4200f412a866278027ba9e433439a03f3b3"
OUTDATED = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
TASK_ID = "cwp-" + "a" * 24


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True,
        timeout=12, check=True,
    )
    return proc.stdout.strip()


def source() -> bytes:
    candidate = (REPO_ROOT / repair.PATH).read_text(encoding="utf-8")
    assert 'RULES_SHA = "' + CANONICAL + '"' in candidate
    return candidate.replace(
        'RULES_SHA = "' + CANONICAL + '"',
        'RULES_SHA = "' + OUTDATED + '"',
    ).encode("utf-8")


def checkout(tmp_path: Path):
    path = tmp_path / "worker"
    file = path / repair.PATH
    file.parent.mkdir(parents=True)
    previous = source()
    file.write_bytes(previous)
    git(path, "init", "-b", "worker/issue42-rules-pin")
    git(path, "add", "--", repair.PATH)
    git(path, "-c", "user.name=Test Builder", "-c",
        "user.email=builder@example.invalid", "commit", "-m", "source baseline")
    base_sha = git(path, "rev-parse", "HEAD")
    task = {
        "task_id": TASK_ID, "repository": repair.REPOSITORY,
        "issue_number": repair.ISSUE,
        "base_sha": base_sha,
        "state": "queued", "fencing_required": True,
        "leased_by": None,
    }
    binding = repair.TrustedTask(
        task_id=TASK_ID, base_sha=base_sha,
        source_sha256=repair.digest(previous), canonical_sha=CANONICAL,
        issue_authorized=True, api_authenticated=True,
        fenced_cutover_attested=True, task=task,
    )
    return path, previous, binding


class SyntheticProposal:
    calls = 0

    def __call__(self, _source, sha):
        self.calls += 1
        output = json.dumps({"rules_sha": sha})
        return {
            "reply": output, "model_calls": 1,
            "model_reply_sha256": repair.digest(output.encode()),
            "model_digest": "synthetic", "eval_count": 0,
            "process_verified": False,
        }


def checker(_path):
    return {"exit_code": 0, "output_within_limit": True,
            "passed_count": 5, "failed_count": 0,
            "error_count": 0, "skipped_count": 0}


def instance(binding, before, model=None, regression=checker):
    return repair.NoteriRulesPinAdapter(
        binding=binding, original=before,
        model=model or SyntheticProposal(),
        regression_runner=regression,
        native_model_required=False,
    )


def manifest(binding, file: bytes, *, produced: str | None = None):
    contract = repair.descriptor()
    return TaskManifest.parse({
        "schema_version": 1, "task_id": TASK_ID,
        "repository": repair.REPOSITORY,
        "base_sha": binding.base_sha,
        "workspace_sha": produced or binding.base_sha,
        "adapter_id": repair.PROFILE,
        "adapter_contract_sha256": contract.contract_sha256,
        "before_sha256": {repair.PATH: repair.digest(file)},
    })


def context(root, binding, before, adapter, role, *, produced=None):
    return AdapterContext(
        root, manifest(binding, before, produced=produced),
        adapter.descriptor, adapter.commands(root), role,
    )


def test_real_git_builder_commit_and_independent_validator_checkout(tmp_path, monkeypatch):
    root, before, binding = checkout(tmp_path)
    monkeypatch.setattr(repair.pin, "canonical_rules_sha", lambda: CANONICAL)
    model = SyntheticProposal()
    adapter = instance(binding, before, model=model)
    assert adapter.descriptor.adapter_id == repair.PROFILE
    assert adapter.descriptor.allowed_paths == (repair.PATH,)
    assert adapter.descriptor.command_keys == (
        repair.CMD_REPAIR, repair.CMD_VALIDATE,
    )
    ctx = context(root, binding, before, adapter, "builder")
    built = adapter.build(ctx)
    assert type(built) is AdapterResult
    assert built.invoked_commands == (repair.CMD_REPAIR,)
    assert built.changed_paths == (repair.PATH,)
    assert re.fullmatch(r"[0-9a-f]{64}", built.evidence_sha256)
    assert built.produced_sha != binding.base_sha
    assert model.calls == 1
    assert git(root, "rev-parse", "HEAD") == built.produced_sha
    assert git(root, "status", "--porcelain") == ""
    assert git(root, "diff", "--name-only", binding.base_sha, built.produced_sha) == repair.PATH
    after = (root / repair.PATH).read_bytes()
    assert after == repair.check_source(before, CANONICAL)

    validator = tmp_path / "different-host-validator"
    git(tmp_path, "clone", "--no-hardlinks", str(root), str(validator))
    git(validator, "remote", "remove", "origin")
    git(validator, "checkout", "--detach", built.produced_sha)
    val_ctx = context(
        validator, binding, after, adapter, "validator", produced=built.produced_sha,
    )
    validated = adapter.validate(val_ctx, built.produced_sha)
    assert type(validated) is AdapterResult
    assert validated.produced_sha == built.produced_sha
    assert validated.invoked_commands == (repair.CMD_VALIDATE,)
    assert git(validator, "status", "--porcelain") == ""
    assert model.calls == 1  # Validator never calls Qwen.


@pytest.mark.parametrize("field,value", [
    ("issue_authorized", False),
    ("api_authenticated", False),
    ("fenced_cutover_attested", False),
])
def test_false_admission_flag_blocks_before_model(tmp_path, field, value):
    _, before, binding = checkout(tmp_path)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_preflight_incomplete"):
        instance(replace(binding, **{field: value}), before)


@pytest.mark.parametrize("key,value", [
    ("repository", "ericson-j-santos/codex-worker-pool-smoke"),
    ("issue_number", 1914),
    ("fencing_required", False),
    ("base_sha", "f" * 40),
    ("state", "completed"),
    ("leased_by", "other"),
])
def test_untrusted_task_rejected_without_model(tmp_path, key, value):
    _, before, binding = checkout(tmp_path)
    tampered = {**binding.task, key: value}
    with pytest.raises(repair.PinAdapterBlocked, match="pin_untrusted_task"):
        instance(replace(binding, task=tampered), before)


@pytest.mark.parametrize("payload", [
    "{}",
    '{"rules_sha":"4e6091a133f8d7d157abe6f83c31ca597812e0a4"}',
    '{"rules_sha":"58dcd4200f412a866278027ba9e433439a03f3b3","path":"evil"}',
    '{"rules_sha":"58dcd4200f412a866278027ba9e433439a03f3b3","command":"git push"}',
    "RULES_SHA = 58dcd4200f412a866278027ba9e433439a03f3b3",
    '{"rules_sha":42}',
])
def test_invalid_model_payload_never_generates_candidate(payload):
    with pytest.raises(repair.PinAdapterBlocked):
        repair.model_candidate(payload, source(), CANONICAL)


def test_default_adapter_rejects_synthetic_model(tmp_path):
    _, before, binding = checkout(tmp_path)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_native_model_required"):
        repair.NoteriRulesPinAdapter(
            binding=binding, original=before,
            model=SyntheticProposal(), regression_runner=checker,
        )


def test_fail_source_already_fixed_or_multiple_assignments():
    current = (REPO_ROOT / repair.PATH).read_bytes()
    with pytest.raises(repair.PinAdapterBlocked, match="pin_source_untrusted"):
        repair.check_source(source() + b"\nRULES_SHA = 'other'\n", CANONICAL)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_baseline_already_repaired"):
        repair.check_source(current, CANONICAL)


def test_builder_rejects_wrong_manifest_before_inference(tmp_path, monkeypatch):
    root, before, binding = checkout(tmp_path)
    monkeypatch.setattr(repair.pin, "canonical_rules_sha", lambda: CANONICAL)
    model = SyntheticProposal()
    adapter = instance(binding, before, model=model)
    wrong = TaskManifest.parse({
        "schema_version": 1, "task_id": TASK_ID,
        "repository": "unknown/bogus",
        "base_sha": binding.base_sha, "workspace_sha": binding.base_sha,
        "adapter_id": repair.PROFILE,
        "adapter_contract_sha256": adapter.descriptor.contract_sha256,
        "before_sha256": {repair.PATH: repair.digest(before)},
    })
    ctx = AdapterContext(root, wrong, adapter.descriptor,
                         adapter.commands(root), "builder")
    with pytest.raises(repair.PinAdapterBlocked, match="pin_manifest_untrusted"):
        adapter.build(ctx)
    assert model.calls == 0
    assert git(root, "status", "--porcelain") == ""


def test_validator_does_not_accept_fake_regression_success(tmp_path, monkeypatch):
    root, before, binding = checkout(tmp_path)
    monkeypatch.setattr(repair.pin, "canonical_rules_sha", lambda: CANONICAL)
    adapter = instance(binding, before)
    built = adapter.build(context(root, binding, before, adapter, "builder"))
    after = (root / repair.PATH).read_bytes()
    bad = instance(binding, before, regression=lambda _: {
        "exit_code": 0, "output_within_limit": True,
        "passed_count": 5, "failed_count": 0,
        "error_count": 0, "skipped_count": 1,
    })
    with pytest.raises(repair.PinAdapterBlocked, match="pin_validator_regressions_unproved"):
        bad.validate(context(root, binding, after, bad, "validator",
                             produced=built.produced_sha), built.produced_sha)


def test_canonical_drift_blocks_before_model_or_write(tmp_path, monkeypatch):
    root, before, binding = checkout(tmp_path)
    monkeypatch.setattr(repair.pin, "canonical_rules_sha", lambda: "c" * 40)
    model = SyntheticProposal()
    adapter = instance(binding, before, model=model)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_canonical_changed"):
        adapter.build(context(root, binding, before, adapter, "builder"))
    assert model.calls == 0
    assert (root / repair.PATH).read_bytes() == before
    assert git(root, "status", "--porcelain") == ""


def test_permission_to_invoke_validator_command_is_not_builder_permission(tmp_path):
    root, before, binding = checkout(tmp_path)
    adapter = instance(binding, before)
    ctx = context(root, binding, before, adapter, "validator")
    from app.native_one_shot import NativeExecutorBlocked
    with pytest.raises(NativeExecutorBlocked, match="command_not_allowlisted"):
        ctx.invoke(repair.CMD_REPAIR)


def test_adapter_never_starts_service_or_chooses_arbitrary_execution():
    data = (REPO_ROOT / "scripts" /
            "noteri_worker_pool_pin_adapter.py").read_text(encoding="utf-8")
    assert "TaskScheduler" not in data
    assert "uvicorn.run" not in data
    assert "workflow_dispatch" not in data
    assert "git push" not in data
    assert "register_worker" not in data
    # The proxy MUST expose a rejecting legacy method while still refusing
    # to forward legacy claims to the underlying transport.
    assert "def claim_exact(" in data
    assert "pin_legacy_claim_forbidden" in data
    assert "_transport.claim_exact(" not in data
    assert "_transport.claim_fenced_exact(" in data
    assert "subprocess.run" not in data



class ReadOnlyFencedTransport:
    def __init__(self, task):
        self.task = dict(task)
        self.legacy_claim_calls = 0
        self.fenced_claim_calls = 0
        self.lifecycle_calls = []

    def get_task(self, task_id):
        assert task_id == self.task["task_id"]
        return dict(self.task)

    def claim_exact(self, *_args, **_kwargs):
        self.legacy_claim_calls += 1
        raise AssertionError("legacy claim must never run")

    def claim_fenced_exact(self, worker_id, task_id, correlation_id):
        self.fenced_claim_calls += 1
        return {"claimed": False, "task_id": task_id}

    def get_latest_checkpoint(self, *args, **kwargs):
        self.lifecycle_calls.append("get_latest_checkpoint")
        return None

    def record_checkpoint(self, *args, **kwargs):
        self.lifecycle_calls.append("record_checkpoint")

    def start(self, *args, **kwargs):
        self.lifecycle_calls.append("start")

    def submit_validation(self, *args, **kwargs):
        self.lifecycle_calls.append("submit_validation")

    def complete(self, *args, **kwargs):
        self.lifecycle_calls.append("complete")

    def fail(self, *args, **kwargs):
        self.lifecycle_calls.append("fail")

    def block(self, *args, **kwargs):
        self.lifecycle_calls.append("block")


def test_fenced_proxy_routes_only_to_exact_fenced_claim_without_legacy(tmp_path):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport(binding.task)
    proxy = repair.FencedOnlyPinApi(transport, binding)
    assert proxy.get_task(binding.task_id)["task_id"] == TASK_ID
    assert proxy.claim_fenced_exact("builder-1", TASK_ID, "issue42-fenced-only") == {
        "claimed": False, "task_id": TASK_ID,
    }
    assert transport.fenced_claim_calls == 1
    assert transport.legacy_claim_calls == 0


@pytest.mark.parametrize("value", [False, 0, "false", None, 2, -1])
def test_fenced_proxy_never_downgrades_when_live_flag_missing_or_false(tmp_path, value):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport({
        **binding.task, "fencing_required": value,
    })
    proxy = repair.FencedOnlyPinApi(transport, binding)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_live_task_not_fenced"):
        proxy.claim_fenced_exact("builder-1", TASK_ID, "issue42-fenced-only")
    assert transport.fenced_claim_calls == 0
    assert transport.legacy_claim_calls == 0


def test_fenced_proxy_sqlite_one_allowed_and_legacy_never(tmp_path):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport({
        **binding.task, "fencing_required": 1,
    })
    proxy = repair.FencedOnlyPinApi(transport, binding)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_legacy_claim_forbidden"):
        proxy.claim_exact("builder", TASK_ID, "issue42")
    assert transport.legacy_claim_calls == 0
    proxy.claim_fenced_exact("builder", TASK_ID, "issue42")
    assert transport.fenced_claim_calls == 1


@pytest.mark.parametrize("bad", [
    {"task_id": "cwp-" + "b" * 24},
    {"repository": "ericson-j-santos/codex-worker-pool-smoke"},
    {"issue_number": 1914},
    {"base_sha": "a" * 40},
])
def test_fenced_proxy_live_identity_drift_blocks_before_claim(tmp_path, bad):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport({**binding.task, **bad})
    proxy = repair.FencedOnlyPinApi(transport, binding)
    with pytest.raises((AssertionError, repair.PinAdapterBlocked)):
        proxy.claim_fenced_exact("builder", TASK_ID, "issue42")
    assert transport.legacy_claim_calls == 0
    assert transport.fenced_claim_calls == 0


@pytest.mark.parametrize("bad", [
    {"state": "running"},
    {"state": "completed"},
    {"leased_by": "another-worker"},
])
def test_fenced_proxy_wrong_live_state_blocks_before_claim(tmp_path, bad):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport({**binding.task, **bad})
    proxy = repair.FencedOnlyPinApi(transport, binding)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_task_not_claimable"):
        proxy.claim_fenced_exact("builder", TASK_ID, "issue42")
    assert transport.legacy_claim_calls == 0
    assert transport.fenced_claim_calls == 0


@pytest.mark.parametrize("method", [
    "start", "submit_validation", "complete", "fail", "block",
    "record_checkpoint", "get_latest_checkpoint",
])
def test_fenced_proxy_lifecycle_bound_to_exact_task(tmp_path, method):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport(binding.task)
    proxy = repair.FencedOnlyPinApi(transport, binding)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_wrong_task_id"):
        getattr(proxy, method)("cwp-" + "c" * 24)
    assert transport.lifecycle_calls == []
    getattr(proxy, method)(TASK_ID)
    assert transport.lifecycle_calls == [method]


def test_fenced_proxy_denies_management_and_arbitrary_api(tmp_path):
    _, _, binding = checkout(tmp_path)
    transport = ReadOnlyFencedTransport(binding.task)
    proxy = repair.FencedOnlyPinApi(transport, binding)
    for attr in ("enqueue_fenced_issue", "register_worker", "_request",
                 "list_repositories", "close", "_client"):
        with pytest.raises(AttributeError):
            getattr(proxy, attr)


def test_fenced_proxy_does_not_authenticate_by_constructor(tmp_path):
    _, _, binding = checkout(tmp_path)
    with pytest.raises(repair.PinAdapterBlocked, match="pin_preflight_incomplete"):
        repair.FencedOnlyPinApi(
            ReadOnlyFencedTransport(binding.task),
            replace(binding, fenced_cutover_attested=False),
        )
