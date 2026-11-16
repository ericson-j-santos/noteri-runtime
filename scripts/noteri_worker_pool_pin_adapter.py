#!/usr/bin/env python3
"""Exact Noteri rules-pin repair adapter for the shared NativeOneShotExecutor.

This module is host-specific; Worker Pool owns fencing, leases, durable CAS and
separate Builder/Validator. No commands, paths or model targets come from a
queue manifest. An operator must separately attest the live issue, rules,
fenced cutover, native Session Launcher and Command Gateway before admission.
Never use this file to provision a service or invoke work from a chat.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from scripts import noteri_worker_pool_rules_pin_sync as pin

REPOSITORY = "ericson-j-santos/noteri-runtime"
ISSUE = 42
PATH = "scripts/noteri_worker_pool_api_runner.py"
PROFILE = "noteri.rules-pin.v1"
MODEL = "qwen2.5-coder:7b"
MODEL_SHA256 = "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364"
CMD_REPAIR = "noteri.pin.repair"
CMD_VALIDATE = "noteri.pin.validate"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
TASK_ID = re.compile(r"cwp-[a-f0-9]{24}\Z")
MAX_SOURCE = 32768


class PinAdapterBlocked(ValueError):
    """Safe failure code without exposing paths, credentials or model output."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PinAdapterBlocked(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_source(original: bytes, target_sha: str) -> bytes:
    """Only the one constant assignment may change; never execute source."""
    require(type(original) is bytes and 0 < len(original) <= MAX_SOURCE,
            "pin_source_untrusted")
    require(type(target_sha) is str and bool(SHA40.fullmatch(target_sha)),
            "pin_rules_sha_untrusted")
    try:
        before = original.decode("utf-8")
        after = pin.candidate_source(before, target_sha)
    except (UnicodeError, pin.SyncBlocked):
        raise PinAdapterBlocked("pin_source_untrusted") from None
    require(after != before, "pin_baseline_already_repaired")
    require(len(after.encode("utf-8")) == len(original),
            "pin_candidate_size_drift")
    try:
        compile(after, PATH, "exec")
    except (SyntaxError, ValueError):
        raise PinAdapterBlocked("pin_candidate_syntax") from None
    return after.encode("utf-8")


def model_candidate(raw: object, original: bytes, target_sha: str) -> bytes:
    """Model chooses exactly one SHA literal, never Python or a command."""
    require(type(raw) is str and 0 < len(raw) <= 1024,
            "pin_model_reply_invalid")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise PinAdapterBlocked("pin_model_reply_invalid") from None
    require(type(data) is dict and set(data) == {"rules_sha"}
            and type(data["rules_sha"]) is str
            and data["rules_sha"] == target_sha,
            "pin_model_proposal_rejected")
    return check_source(original, data["rules_sha"])


@dataclass(frozen=True)
class TrustedTask:
    """Only construct from independently authenticated API/issue preflight."""

    task_id: str
    base_sha: str
    source_sha256: str
    canonical_sha: str
    issue_authorized: bool
    api_authenticated: bool
    fenced_cutover_attested: bool
    task: Mapping[str, Any]

    def check(self) -> None:
        require(bool(TASK_ID.fullmatch(self.task_id))
                and bool(SHA40.fullmatch(self.base_sha))
                and bool(re.fullmatch(r"[a-f0-9]{64}", self.source_sha256))
                and bool(SHA40.fullmatch(self.canonical_sha))
                and self.issue_authorized is True
                and self.api_authenticated is True
                and self.fenced_cutover_attested is True
                and type(self.task) is dict,
                "pin_preflight_incomplete")
        require(self.task.get("task_id") == self.task_id
                and self.task.get("repository") == REPOSITORY
                and self.task.get("issue_number") == ISSUE
                and self.task.get("base_sha") == self.base_sha
                and self.task.get("fencing_required") is True
                and self.task.get("state") in {"queued", "validating"}
                and self.task.get("leased_by") is None
                and self.task_id != "cwp-0d3af2bcbd0f5fd0f4cc7386",
                "pin_untrusted_task")


class NativeQwenPinProposal:
    """One real, local, GGUF Qwen7B call; never download or use remote models."""

    def __call__(self, original: bytes, target_sha: str) -> dict[str, Any]:
        from app.native_structured_ollama import NativeStructuredOllama
        from app.local_code_worker import OLLAMA_URL
        import httpx

        require(os.environ.get("OLLAMA_NO_CLOUD") == "1"
                and os.environ.get("NATIVE_OLLAMA_DEV") == "1"
                and os.environ.get("NATIVE_MODEL_DIGEST_PREFIX") == MODEL_SHA256,
                "pin_model_policy_not_attested")
        NativeStructuredOllama.no_cloud()
        require(OLLAMA_URL == "http://127.0.0.1:11434",
                "pin_model_not_loopback")
        # The model only sees the one old constant and the new canonical SHA.
        previous = pin.pinned_sha(original.decode("utf-8"))
        require(previous != target_sha, "pin_baseline_already_repaired")
        with httpx.Client(base_url=OLLAMA_URL, timeout=120, trust_env=False,
                          follow_redirects=False) as client:
            models = NativeStructuredOllama.request(
                client, "GET", "/api/tags").get("models")
            selected = NativeStructuredOllama.select_model(models)
            require(selected.get("name") == MODEL
                    and selected.get("digest") == MODEL_SHA256
                    and not selected.get("remote_host")
                    and not selected.get("remote_model"),
                    "pin_model_digest_untrusted")
            info = NativeStructuredOllama.request(
                client, "POST", "/api/show", json={"model": MODEL})
            require(not info.get("remote_host") and not info.get("remote_model")
                    and type(info.get("details")) is dict
                    and info["details"].get("format") == "gguf",
                    "pin_model_weights_untrusted")
            result = NativeStructuredOllama.request(
                client, "POST", "/api/chat", json={
                    "model": MODEL, "stream": False, "keep_alive": "5m",
                    "messages": [
                        {"role": "system", "content":
                         "Repair exactly one outdated SHA literal. Return only "
                         "a JSON object with rules_sha. Never return code, paths, "
                         "commands, explanations or other keys."},
                        {"role": "user", "content":
                         f"Current RULES_SHA: {previous}\n"
                         f"Authoritative rules main SHA: {target_sha}\n"
                         "Return the corrected rules_sha literal in JSON."},
                    ],
                    "format": {"type": "object", "properties": {
                        "rules_sha": {"type": "string", "pattern":
                                      "^[0-9a-f]{40}$"}},
                        "required": ["rules_sha"],
                        "additionalProperties": False},
                    "options": {"temperature": 0, "seed": 7,
                                "num_predict": 96, "num_ctx": 2048},
                })
            require(result.get("done") is True
                    and result.get("model") == MODEL
                    and type(result.get("eval_count")) is int
                    and result["eval_count"] > 0,
                    "pin_inference_not_proved")
            running = NativeStructuredOllama.request(
                client, "GET", "/api/ps").get("models")
            require(type(running) is list and any(
                type(item) is dict and item.get("name") == MODEL
                and item.get("digest") == MODEL_SHA256
                and type(item.get("size")) is int and item["size"] > 0
                and not item.get("remote_host")
                and not item.get("remote_model")
                for item in running), "pin_model_process_not_proved")
        NativeStructuredOllama.no_cloud()
        msg = result.get("message")
        require(type(msg) is dict and type(msg.get("content")) is str,
                "pin_model_reply_invalid")
        reply = msg["content"]
        model_candidate(reply, original, target_sha)
        return {"reply": reply, "model_calls": 1,
                "model_digest": MODEL_SHA256,
                "model_reply_sha256": digest(reply.encode("utf-8")),
                "eval_count": result["eval_count"],
                "process_verified": True}


def descriptor() -> Any:
    # Reuse the real, pinned shared Worker Pool contract at runtime.
    from app.native_one_shot import AdapterDescriptor
    return AdapterDescriptor(
        adapter_id=PROFILE, allowed_paths=(PATH,),
        builder_commands=(CMD_REPAIR,), validator_commands=(CMD_VALIDATE,),
    )


class NoteriRulesPinAdapter:
    """Fixed adapter; NativeOneShotExecutor performs fenced claim and CAS."""

    def __init__(self, *, binding: TrustedTask, original: bytes,
                 model: Any, regression_runner: Callable[[Path], Mapping[str, Any]],
                 native_model_required: bool = True):
        require(type(binding) is TrustedTask, "pin_binding_untrusted")
        binding.check()
        require(type(original) is bytes
                and digest(original) == binding.source_sha256,
                "pin_before_hash_mismatch")
        check_source(original, binding.canonical_sha)
        # Tests may explicitly run synthetic proposals. Production always
        # requires this concrete local model provider and its real receipt.
        require(type(native_model_required) is bool and callable(model)
                and callable(regression_runner), "pin_handlers_untrusted")
        if native_model_required:
            require(type(model) is NativeQwenPinProposal,
                    "pin_native_model_required")
        self.binding = binding
        self.original = original
        self.model = model
        self.native_model_required = native_model_required
        self.regression_runner = regression_runner
        self.descriptor = descriptor()

    @staticmethod
    def _file(root: Path) -> Path:
        file = root / PATH
        require(root.is_dir() and not root.is_symlink()
                and file.parent.is_dir() and not file.parent.is_symlink()
                and file.is_file() and not file.is_symlink()
                and file.stat().st_nlink == 1
                and file.resolve().is_relative_to(root.resolve()),
                "pin_file_unsafe")
        return file

    def _manifest(self, context: Any, *, role: str, produced_sha: str = "") -> None:
        manifest = context.manifest
        self.binding.check()
        require(manifest.repository == REPOSITORY
                and manifest.task_id == self.binding.task_id
                and manifest.base_sha == self.binding.base_sha
                and manifest.adapter_id == PROFILE
                and manifest.adapter_contract_sha256 ==
                    self.descriptor.contract_sha256
                and set(manifest.before_sha256) == {PATH},
                "pin_manifest_untrusted")
        if role == "builder":
            require(manifest.workspace_sha == self.binding.base_sha
                    and manifest.before_sha256[PATH] ==
                        self.binding.source_sha256,
                    "pin_builder_workspace_drift")
        else:
            require(manifest.workspace_sha == produced_sha
                    and produced_sha != self.binding.base_sha
                    and manifest.before_sha256[PATH] ==
                        digest(self._file(context.root).read_bytes()),
                    "pin_validator_workspace_drift")

    def commands(self, root: Path) -> dict[str, Callable[[], dict[str, Any]]]:
        def repair() -> dict[str, Any]:
            from app.structured_code_worker import clean_git_configuration, git
            file = self._file(root)
            before = file.read_bytes()
            require(before == self.original, "pin_before_drift")
            clean_git_configuration(root)
            require(git(root, "remote") == ""
                    and git(root, "branch", "--show-current").startswith("worker/")
                    and git(root, "rev-parse", "HEAD") == self.binding.base_sha
                    and git(root, "status", "--porcelain", "--untracked-files=all") == "",
                    "pin_git_boundary")
            require(pin.canonical_rules_sha() == self.binding.canonical_sha,
                    "pin_canonical_changed")
            outcome = self.model(before, self.binding.canonical_sha)
            require(type(outcome) is dict
                    and outcome.get("model_calls") == 1
                    and type(outcome.get("reply")) is str,
                    "pin_model_not_invoked")
            if self.native_model_required:
                require(outcome.get("process_verified") is True
                        and outcome.get("model_digest") == MODEL_SHA256
                        and type(outcome.get("eval_count")) is int
                        and outcome["eval_count"] > 0
                        and outcome.get("model_reply_sha256") ==
                            digest(outcome["reply"].encode("utf-8")),
                        "pin_model_attestation_invalid")
            after = model_candidate(outcome["reply"], before,
                                    self.binding.canonical_sha)
            require(file.read_bytes() == before and
                    git(root, "status", "--porcelain", "--untracked-files=all") == "",
                    "pin_concurrent_change")
            file.write_bytes(after)
            try:
                require(git(root, "diff", "--name-only") == PATH,
                        "pin_diff_scope")
                git(root, "diff", "--check")
                patch = (git(root, "diff", "--", PATH) + "\n").encode("utf-8")
                git(root, "add", "--", PATH)
                require(git(root, "diff", "--cached", "--name-only") == PATH,
                        "pin_staged_scope")
                git(root, "-c", "user.name=Noteri Rules Pin Builder",
                    "-c", "user.email=worker@localhost", "commit",
                    "-m", "fix: restore canonical Noteri Worker Pool rules SHA")
                produced = git(root, "rev-parse", "HEAD")
                require(produced != self.binding.base_sha
                        and git(root, "status", "--porcelain") == ""
                        and git(root, "diff", "--name-only",
                                self.binding.base_sha, produced) == PATH,
                        "pin_commit_unproved")
                require(file.read_bytes() == after, "pin_post_commit_drift")
                return {"produced_sha": produced,
                        "patch_sha256": digest(patch),
                        "model_reply_sha256": outcome["model_reply_sha256"],
                        "model_calls": 1}
            except Exception:
                # Never reset a possibly committed checkout or hide an
                # ambiguous state. The coordinator must block/reconcile it.
                raise

        def independently_validate() -> dict[str, Any]:
            from app.structured_code_worker import clean_git_configuration, git
            file = self._file(root)
            after = file.read_bytes()
            require(after == check_source(self.original,
                                          self.binding.canonical_sha),
                    "pin_validator_not_exact")
            require(pin.canonical_rules_sha() == self.binding.canonical_sha,
                    "pin_canonical_changed")
            clean_git_configuration(root)
            require(git(root, "remote") == ""
                    and git(root, "status", "--porcelain", "--untracked-files=all") == "",
                    "pin_validator_git_boundary")
            observed = self.regression_runner(root)
            require(type(observed) is dict
                    and observed.get("exit_code") == 0
                    and observed.get("output_within_limit") is True
                    and observed.get("failed_count") == 0
                    and observed.get("error_count") == 0
                    and observed.get("skipped_count") == 0
                    and type(observed.get("passed_count")) is int
                    and observed["passed_count"] > 0,
                    "pin_validator_regressions_unproved")
            return {"source_sha256": digest(after),
                    "passed_count": observed["passed_count"]}

        return {CMD_REPAIR: repair, CMD_VALIDATE: independently_validate}

    def build(self, context: Any) -> Any:
        from app.native_one_shot import AdapterResult
        self._manifest(context, role="builder")
        require(self._file(context.root).read_bytes() == self.original,
                "pin_before_drift")
        receipt = context.invoke(CMD_REPAIR)
        require(type(receipt) is dict
                and bool(SHA40.fullmatch(str(receipt.get("produced_sha"))))
                and bool(re.fullmatch(r"[0-9a-f]{64}",
                                      str(receipt.get("patch_sha256")))),
                "pin_builder_receipt_untrusted")
        return AdapterResult(
            produced_sha=receipt["produced_sha"],
            changed_paths=(PATH,),
            invoked_commands=tuple(context.invoked),
            evidence_sha256=receipt["patch_sha256"],
        )

    def validate(self, context: Any, produced_sha: str) -> Any:
        from app.native_one_shot import AdapterResult
        require(bool(SHA40.fullmatch(produced_sha)),
                "pin_validator_sha_invalid")
        self._manifest(context, role="validator", produced_sha=produced_sha)
        result = context.invoke(CMD_VALIDATE)
        require(type(result) is dict
                and result.get("source_sha256") ==
                    digest(self._file(context.root).read_bytes()),
                "pin_validator_receipt_invalid")
        receipt = digest(json.dumps(
            {"produced_sha": produced_sha, "proof": result},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
        return AdapterResult(
            produced_sha=produced_sha,
            changed_paths=(PATH,),
            invoked_commands=tuple(context.invoked),
            evidence_sha256=receipt,
        )
