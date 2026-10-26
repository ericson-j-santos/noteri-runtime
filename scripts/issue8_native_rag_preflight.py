"""Read-only physical admission and real issue-scoped Qwen RAG on Noteri.

Everything here is deliberately pre-PR: no lease, commands chosen by a model,
CAS writes, code modification, Git push or deployment. The trusted Builder/
Validator/CAS code lives exclusively in the SHA-pinned Worker Pool checkout.

Run ONLY via the canonical Session Launcher + Command Gateway on an authorized
Noteri runner after hosted owner/HEAD and CI admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOST_REPOSITORY = "ericson-j-santos/noteri-runtime"
WORKER_REPOSITORY = "ericson-j-santos/engineering-worker-pool"
WORKER_SHA = "047c77b6b867ff5d489bd74f6fd80989719ab85e"
RULES_SHA = "8af10e2cf85f18f14ba12fbbeb4afc8b8320bbe8"
SOURCE_PATH = "app/portfolio_bridge.py"
SOURCE_BLOB_SHA = "d9a25c574163c49f695e774609949160d94f4490"
ISSUE_NUMBER = 8
OWNER_COMMENT_ID = 6423646539
MODEL_PIN = "dae161e27b0e"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
CORRELATION = re.compile(r"[a-z0-9][a-z0-9-]{7,120}\Z")


_PHASE = "identity"
_PHASES = frozenset((
    "identity", "checkouts", "agent_core", "imports", "owner",
    "baseline", "model", "research", "readback",
))

def _set_phase(phase: str) -> None:
    global _PHASE
    if phase not in _PHASES:
        raise PreflightBlocked("issue8_phase_invalid")
    _PHASE = phase


class PreflightBlocked(RuntimeError):
    """Never contain user input, remote API body, paths, or credentials."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise PreflightBlocked(code)


def inspect_native_model_inventory(models: object, model_name: str, digest_pin: str) -> str:
    """Classify the real Ollama tag inventory before the pinned worker attestations.

    No model is installed, retagged, downloaded or selected by a task payload.
    The trusted Worker Pool still performs digest/GGUF/local-process checks.
    """
    require(type(models) is list and 1 <= len(models) <= 64
            and all(type(item) is dict for item in models),
            "issue8_model_inventory_invalid")
    named = [item for item in models if item.get("name") == model_name]
    if not named:
        pinned_elsewhere = any(
            type(item.get("digest")) is str
            and SHA64.fullmatch(item["digest"]) is not None
            and item["digest"].startswith(digest_pin)
            for item in models
        )
        raise PreflightBlocked(
            "issue8_model_pinned_under_other_tag" if pinned_elsewhere
            else "issue8_model_tag_missing"
        )
    require(len(named) == 1, "issue8_model_tag_duplicate")
    return "tag_present"


def probe_native_model() -> None:
    """Read only /api/tags on the reviewed loopback client; fail closed."""
    import httpx
    from app.local_code_worker import LocalOllama, OLLAMA_URL
    from app.structured_ollama import MODEL
    from app.native_structured_ollama import NativeStructuredOllama

    NativeStructuredOllama.no_cloud()
    with httpx.Client(base_url=OLLAMA_URL, timeout=15,
                      trust_env=False, follow_redirects=False) as client:
        models = LocalOllama.request(client, "GET", "/api/tags").get("models")
    inspect_native_model_inventory(models, MODEL, MODEL_PIN)
    # Retain the Worker Pool's exact-tag/digest/GGUF/remote-host gate.
    NativeStructuredOllama.select_model(models)


def _local_ollama_tags() -> list[dict[str, object]]:
    """Only GET localhost; never follow redirects or honor proxy settings."""
    from urllib import request

    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open("http://127.0.0.1:11434/api/tags", timeout=15) as response:
            require(response.status == 200, "issue8_ollama_local_api_unavailable")
            raw = response.read(262145)
    except (OSError, ValueError):
        raise PreflightBlocked("issue8_ollama_local_api_unavailable") from None
    require(0 < len(raw) <= 262144, "issue8_ollama_local_tags_invalid")
    try:
        doc = json.loads(raw)
    except (TypeError, ValueError):
        raise PreflightBlocked("issue8_ollama_local_tags_invalid") from None
    require(type(doc) is dict and type(doc.get("models")) is list,
            "issue8_ollama_local_tags_invalid")
    return doc["models"]


def inspect_ollama_model_store(*, model_root: Path | None = None,
                               inventory: object = None,
                               disk_usage=None) -> dict[str, object]:
    """Attest model storage to live tags via Git manifest SHA-256, read-only.

    Default models location alone is not accepted as proof of a running daemon's
    storage. A manifest must hash to one of the exact local Ollama /api/tags
    digests. No personal paths are emitted.
    """
    import platform
    import shutil
    import socket

    require(platform.system() == "Windows" and socket.gethostname() == "Noteri",
            "issue8_model_host_unverified")
    supplied = os.environ.get("OLLAMA_MODELS", "").strip()
    root = model_root if model_root is not None else (
        Path(supplied) if supplied else Path.home() / ".ollama" / "models"
    )
    require(root.is_absolute() and root.is_dir() and not root.is_symlink()
            and not getattr(root, "is_junction", lambda: False)(),
            "issue8_model_storage_root_unverified")
    measure = disk_usage if disk_usage is not None else shutil.disk_usage
    free = measure(root).free
    require(type(free) is int and free >= 10 * 1024 ** 3,
            "issue8_model_storage_insufficient")
    models = _local_ollama_tags() if inventory is None else inventory
    require(type(models) is list and len(models) <= 64
            and all(type(item) is dict for item in models),
            "issue8_model_inventory_invalid")
    manifests = root / "manifests" / "registry.ollama.ai" / "library"
    verified = 0
    model_present = False
    for item in models:
        name, digest = item.get("name"), item.get("digest")
        if (type(name) is not str or type(digest) is not str
                or SHA64.fullmatch(digest) is None):
            continue
        if name == "qwen2.5-coder:7b":
            require(digest.startswith(MODEL_PIN), "issue8_model_digest_mismatch")
            model_present = True
        match = re.fullmatch(r"([a-z0-9][a-z0-9._-]{0,60}):([a-z0-9][a-z0-9._-]{0,60})", name)
        if match is None:
            continue
        path = manifests / match.group(1) / match.group(2)
        if not path.is_file() or path.is_symlink():
            continue
        require(path.stat().st_size <= 65536,
                "issue8_model_manifest_invalid")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() == digest:
            verified += 1
    require(verified >= 1, "issue8_model_storage_not_attested")
    return {
        "result": "ISSUE8_MODEL_STORAGE_READONLY_VERIFIED",
        "model_store_bound_to_daemon": True,
        "free_gib": round(free / 1024 ** 3, 2),
        "manifest_matches": verified,
        "qwen_tag_present": model_present,
        "state_changed": False,
    }




def _post_ollama_fixed_model(endpoint: str, payload: dict[str, object]):
    """Fixed, loopback-only Ollama API, with neither proxies nor redirects."""
    from urllib import request

    require(endpoint in {"/api/pull", "/api/show"},
            "issue8_model_api_endpoint_invalid")

    class RefuseRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None

    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    opener = request.build_opener(request.ProxyHandler({}), RefuseRedirect())
    return opener.open(
        request.Request("http://127.0.0.1:11434" + endpoint,
                        data=body, method="POST",
                        headers={"Content-Type": "application/json"}),
        timeout=45,
    )


def _pull_exact_ollama_model(*, provider=None, clock=None) -> None:
    """Single opt-in 7B download, bounded by time and material byte progress."""
    import time

    now = time.monotonic if clock is None else clock
    post = _post_ollama_fixed_model if provider is None else provider
    started = last_progress = now()
    bytes_by_layer: dict[str, int] = {}
    success = False
    with post("/api/pull", {"model": "qwen2.5-coder:7b",
                            "stream": True, "insecure": False}) as response:
        require(response.status == 200, "issue8_model_registry_unavailable")
        while True:
            current = now()
            require(current - started <= 720, "issue8_model_download_timeout")
            require(current - last_progress <= 300, "issue8_model_no_progress")
            row = response.readline(4097)
            if not row:
                break
            require(len(row) <= 4096, "issue8_model_progress_invalid")
            try:
                event = json.loads(row)
            except (ValueError, TypeError):
                raise PreflightBlocked("issue8_model_progress_invalid") from None
            require(type(event) is dict and not event.get("error"),
                    "issue8_model_registry_error")
            if event.get("status") == "success":
                success = True
                break
            size = event.get("completed")
            if size is not None:
                require(type(size) is int and 0 <= size <= 8_000_000_000,
                        "issue8_model_progress_invalid")
                layer = event.get("digest", "")
                require(type(layer) is str and len(layer) <= 128,
                        "issue8_model_progress_invalid")
                if size > bytes_by_layer.get(layer, 0):
                    bytes_by_layer[layer] = size
                    last_progress = now()
    require(success, "issue8_model_download_unconfirmed")


def _verify_local_qwen7b() -> dict[str, object]:
    models = _local_ollama_tags()
    selected = [x for x in models if type(x) is dict
                and x.get("name") == "qwen2.5-coder:7b"]
    require(len(selected) == 1, "issue8_model_tag_absent_or_duplicate")
    item = selected[0]
    digest, size = item.get("digest"), item.get("size")
    require(type(digest) is str and SHA64.fullmatch(digest) is not None
            and digest.startswith(MODEL_PIN),
            "issue8_model_digest_mismatch")
    require(type(size) is int and 4_000_000_000 <= size <= 8_000_000_000
            and type(item.get("details")) is dict
            and item["details"].get("format") == "gguf"
            and not item.get("remote_host") and not item.get("remote_model"),
            "issue8_model_local_gguf_unverified")
    with _post_ollama_fixed_model("/api/show",
                                  {"model": "qwen2.5-coder:7b"}) as response:
        require(response.status == 200, "issue8_model_metadata_unavailable")
        raw = response.read(262145)
    require(0 < len(raw) <= 262144, "issue8_model_metadata_invalid")
    try:
        metadata = json.loads(raw)
    except (ValueError, TypeError):
        raise PreflightBlocked("issue8_model_metadata_invalid") from None
    require(type(metadata) is dict and type(metadata.get("details")) is dict
            and metadata["details"].get("format") == "gguf"
            and not metadata.get("remote_host") and not metadata.get("remote_model"),
            "issue8_model_metadata_invalid")
    return {"digest": digest, "size": size}


def provision_ollama_qwen7b(mode: str) -> dict[str, object]:
    """Explicit Gateway Risk2 install or Risk1 verification; RAG remains read-only."""
    require(mode in {"install", "verify"}, "issue8_model_mode_invalid")
    before = inspect_ollama_model_store()
    changed = False
    if mode == "install" and not before["qwen_tag_present"]:
        _pull_exact_ollama_model()
        changed = True
    metadata = _verify_local_qwen7b()
    after = inspect_ollama_model_store()
    require(after["qwen_tag_present"] is True and
            after["model_store_bound_to_daemon"] is True,
            "issue8_model_final_readback_invalid")
    return {
        "result": "ISSUE8_OLLAMA_QWEN7B_VERIFIED",
        "mode": mode,
        "model_name": "qwen2.5-coder:7b",
        "digest": metadata["digest"],
        "size": metadata["size"],
        "model_state_changed": changed,
        "git_state_changed": False,
    }


def validate_environment(env: dict[str, str]) -> dict[str, str]:
    require(env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_REPOSITORY") == HOST_REPOSITORY,
            "issue8_actions_repository_invalid")
    require(env.get("RUNNER_NAME") == "Noteri-runtime",
            "issue8_wrong_runner")
    require(env.get("NATIVE_OLLAMA_DEV") == "1"
            and env.get("NATIVE_MODEL_DIGEST_PREFIX") == MODEL_PIN,
            "issue8_model_not_approved")
    require(env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
            and env.get("SESSION_STATE_VALIDATED") == "true"
            and env.get("SESSION_GATEWAY_BOUND") == "true",
            "issue8_session_or_gateway_unverified")
    session = env.get("SESSION_ID", "")
    snapshot = env.get("SESSION_SNAPSHOT_SHA256", "")
    correlation = env.get("CORRELATION_ID", "")
    runtime_sha = env.get("EXPECTED_NOTERI_SHA", "")
    run, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    require(bool(re.fullmatch(r"[A-Za-z0-9._-]{3,64}", session)),
            "issue8_session_invalid")
    require(bool(SHA64.fullmatch(snapshot)),
            "issue8_session_snapshot_invalid")
    require(bool(CORRELATION.fullmatch(correlation)),
            "issue8_correlation_invalid")
    require(bool(SHA40.fullmatch(runtime_sha)),
            "issue8_host_sha_invalid")
    require(run.isdigit() and len(run) <= 20
            and attempt.isdigit() and 1 <= int(attempt) <= 20,
            "issue8_run_identity_invalid")
    require(env.get("WORKER_POOL_SHA") == WORKER_SHA
            and env.get("RULES_SHA") == RULES_SHA,
            "issue8_pinned_source_mismatch")
    workspace = env.get("GITHUB_WORKSPACE", "")
    require(bool(workspace), "issue8_checkout_path_missing")
    return {
        "runtime_sha": runtime_sha, "correlation_id": correlation,
        "session_id": session, "snapshot_sha256": snapshot,
        "run_id": run, "attempt": attempt, "workspace": workspace,
    }


def read_git(root: Path, *args: str) -> str:
    require(root.is_dir() and not root.is_symlink(),
            "issue8_pinned_checkout_missing")
    actions = {
        ("rev-parse", "HEAD"): "sha",
        ("status", "--porcelain", "--untracked-files=no"): "status",
    }
    action = actions.get(tuple(args))
    require(action is not None, "issue8_git_action_not_allowlisted")
    local_env = dict(os.environ)
    local_env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        r = subprocess.run(
            ["git", *args], cwd=root, env=local_env,
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightBlocked(f"issue8_git_{action}_unavailable") from None
    require(r.returncode == 0 and not r.stderr.strip()
            and len(r.stdout) <= 4096,
            f"issue8_git_{action}_invalid")
    return r.stdout.strip()


def canonical_git_source(worker: Path) -> bytes:
    """Return exact pinned Git blob bytes, not platform-converted checkout."""
    require(worker.is_dir() and not worker.is_symlink(),
            "issue8_pinned_checkout_missing")
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    argv = ["git", "show", "HEAD:" + SOURCE_PATH]
    try:
        result = subprocess.run(
            argv, cwd=worker, env=env, capture_output=True,
            text=False, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightBlocked("issue8_git_blob_unavailable") from None
    require(result.returncode == 0 and
            type(result.stdout) is bytes and
            type(result.stderr) is bytes and not result.stderr and
            0 < len(result.stdout) <= 262_144,
            "issue8_git_blob_invalid")
    raw = result.stdout
    blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()
    require(blob == SOURCE_BLOB_SHA, "issue8_source_blob_drift")
    return raw


def verify_pinned_checkout(env: dict[str, str], identity: dict[str, str]) -> tuple[Path, bytes]:
    workspace = Path(identity["workspace"]).resolve(strict=True)
    rules = workspace / "_rules"
    worker = workspace / "_worker_pool"
    host = Path(env.get("SESSION_TARGET_PATH", "")).resolve(strict=True)
    require(host.is_dir() and host != workspace
            and (host / "scripts" / "issue8_native_rag_preflight.py").is_file(),
            "issue8_governed_worktree_invalid")
    for repo, pinned in (
        (host, identity["runtime_sha"]),
        (worker, WORKER_SHA),
        (rules, RULES_SHA),
    ):
        require(read_git(repo, "rev-parse", "HEAD") == pinned,
                "issue8_checkout_sha_drift")
        require(read_git(repo, "status", "--porcelain", "--untracked-files=no") == "",
                "issue8_checkout_dirty")
    source = worker / SOURCE_PATH
    require(source.is_file() and not source.is_symlink()
            and source.resolve().is_relative_to(worker.resolve()),
            "issue8_source_missing")
    # Git's object database is the canonical source. Git for Windows may
    # materialize LF blobs as CRLF files without marking the worktree dirty.
    # Never hash the checkout bytes and call them the Git blob.
    raw = canonical_git_source(worker)
    worktree = source.read_bytes()
    require(worktree == raw or (
                b"\r\n" not in raw and worktree == raw.replace(b"\n", b"\r\n")
            ), "issue8_checkout_bytes_drift")
    return worker, raw


def read_original_bytes(reader: object, path: str, sha: str) -> bytes:
    require(sha == WORKER_SHA and
            path in {"README.md", "AGENTS.md",
                     "docs/ISSUE_QWEN7B_DRAFT_HANDOFF.md"},
            "issue8_independent_path_invalid")
    try:
        obj = reader.get_text_file(WORKER_REPOSITORY, path, sha)
        require(type(obj) is dict and obj.get("type") == "file"
                and obj.get("path") == path
                and obj.get("encoding") == "base64"
                and type(obj.get("size")) is int
                and 0 < obj["size"] <= 65536
                and type(obj.get("content")) is str,
                "issue8_independent_blob_invalid")
        raw = base64.b64decode(
            obj["content"].replace("\n", ""), validate=True,
        )
        require(len(raw) == obj["size"], "issue8_independent_blob_invalid")
        require(hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
        ).hexdigest() == obj.get("sha"),
                "issue8_independent_blob_drift")
        return raw
    except PreflightBlocked:
        raise
    except Exception:
        raise PreflightBlocked("issue8_independent_api_unavailable") from None


def run(env: dict[str, str]) -> dict[str, object]:
    _set_phase('identity')
    identity = validate_environment(env)
    _set_phase('checkouts')
    worker, original = verify_pinned_checkout(env, identity)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(worker))
    _set_phase('agent_core')
    agent = Path(identity["workspace"]) / "_agent_core"
    require(read_git(agent, "rev-parse", "HEAD")
            == "1fc032d4c412bdb4ed202cf1193caf0cb49490ce",
            "issue8_agent_core_sha_drift")
    sys.path.insert(0, str(agent))

    _set_phase('imports')
    from app.issue_draft_pr import admit, trusted_task
    from app.structured_code_worker import validate
    from app.issue_rag_research import official_issue_reader, research_issue
    from app.issue_rag_handoff import bind_issue_rag
    from app.native_structured_ollama import NativeStructuredOllama

    # Independent live GitHub read; no synthetic issue or pre-authorized JSON.
    _set_phase('owner')
    public_api = official_issue_reader(env.get("GITHUB_TOKEN") or None)
    now = datetime.now(timezone.utc)
    approved = admit(
        public_api.get_issue(ISSUE_NUMBER),
        public_api.get_comment(OWNER_COMMENT_ID),
        public_api.get_branch("main"),
        base_sha=WORKER_SHA,
        observed_at=now.isoformat(), now=now,
    )
    task = trusted_task(approved, original)
    _set_phase('baseline')
    baseline = validate(original.decode("utf-8"), task)
    require(type(baseline) is dict and baseline.get("total") == 42
            and type(baseline.get("passed")) is int
            and 0 <= baseline["passed"] < 42,
            "issue8_baseline_not_reproducible")

    # Real Ollama calls must occur ONLY after the above owner/HEAD/baseline
    # gates. NativeStructuredOllama checks GGUF digest and no cloud endpoints.
    _set_phase('model')
    NativeStructuredOllama.no_cloud()
    probe_native_model()
    _set_phase('research')
    receipt = research_issue(approved, github_token=env.get("GITHUB_TOKEN") or None)
    require(type(receipt) is dict and
            receipt.get("schema_version") == "worker.rag.issue-context-v1"
            and receipt.get("head_sha") == WORKER_SHA
            and receipt.get("issue_number") == ISSUE_NUMBER
            and receipt.get("state") == "supported"
            and receipt.get("model_process_verified") is True
            and receipt.get("issue_head_readback_stable") is True
            and receipt.get("execution_authorized") is False
            and receipt.get("state_changed") is False
            and type(receipt.get("model_calls")) is int
            and 2 <= receipt["model_calls"] <= 4,
            "issue8_real_rag_not_verified")

    # Separate API client validates the exact cited bytes after inference.
    _set_phase('readback')
    independent = official_issue_reader(env.get("GITHUB_TOKEN") or None)
    citation = bind_issue_rag(
        approved, receipt,
        lambda path, sha: read_original_bytes(independent, path, sha),
    )
    current = independent.get_branch("main").get("commit", {}).get("sha")
    require(current == WORKER_SHA, "issue8_main_changed_after_rag")
    _, post_source = verify_pinned_checkout(env, identity)
    require(post_source == original, "issue8_worker_modified")
    result = {
        "result": "ISSUE8_NATIVE_RAG_PREFLIGHT_VERIFIED",
        "schema_version": "issue8.native.rag.readonly-v1",
        "issue_number": ISSUE_NUMBER,
        "worker_sha": WORKER_SHA,
        "runtime_sha": identity["runtime_sha"],
        "rules_sha": RULES_SHA,
        "model_calls": receipt["model_calls"],
        "model_digest_prefix": citation.model_digest[:12],
        "baseline_total": baseline["total"],
        "baseline_passed": baseline["passed"],
        "citation_path": citation.source_path,
        "citation_line": citation.line,
        "source_sha256": citation.source_sha256,
        "receipt_sha256": citation.receipt_sha256,
        "independent_git_source_readback": True,
        "session_result": "SESSION_LAUNCH_OK",
        "session_id": identity["session_id"],
        "snapshot_sha256": identity["snapshot_sha256"],
        "correlation_id": identity["correlation_id"],
        "run_id": identity["run_id"],
        "run_attempt": identity["attempt"],
        "state_changed": False,
        "cas_write": False,
        "draft_pr_created": False,
        "model_commands_authorized": False,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    # Explicit argv keeps embedded/test callers independent from the host process
    # arguments while preserving normal command-line behavior for the entrypoint.
    args = sys.argv[1:] if argv is None else argv
    if args in (["--install-ollama-qwen7b"], ["--verify-ollama-qwen7b"]):
        mode = "install" if args == ["--install-ollama-qwen7b"] else "verify"
        try:
            observed = provision_ollama_qwen7b(mode)
        except PreflightBlocked as exc:
            print(json.dumps({"result": "ISSUE8_MODEL_SETUP_BLOCKED",
                              "reason_code": str(exc)}, sort_keys=True))
            return 2
        except Exception:
            print(json.dumps({"result": "ISSUE8_MODEL_SETUP_BLOCKED",
                              "reason_code": "issue8_model_dependency_unavailable"},
                             sort_keys=True))
            return 2
        print(json.dumps(observed, sort_keys=True))
        return 0
    if args == ["--inspect-ollama-model-store"]:
        try:
            result = inspect_ollama_model_store()
        except PreflightBlocked as exc:
            print(json.dumps({"result": "ISSUE8_MODEL_STORAGE_BLOCKED",
                              "reason_code": str(exc)}, sort_keys=True))
            return 2
        except Exception:
            print(json.dumps({"result": "ISSUE8_MODEL_STORAGE_BLOCKED",
                              "reason_code": "issue8_model_storage_dependency_unavailable"},
                             sort_keys=True))
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if args:
        print(json.dumps({"result": "ISSUE8_MODEL_STORAGE_BLOCKED",
                          "reason_code": "issue8_cli_mode_invalid"}, sort_keys=True))
        return 2
    try:
        observed = run(dict(os.environ))
    except Exception as exc:
        code = (
            str(exc) if (
                (
                    type(exc) is PreflightBlocked or
                    (type(exc).__module__, type(exc).__name__) in {
                        ("app.issue_draft_pr", "HandoffBlocked"),
                        ("app.structured_code_worker", "StructuredBlocked"),
                        ("app.agent_rag_consumer", "ResearchBlocked"),
                        ("agent_core.contracts", "Blocked"),
                    }
                )
                and re.fullmatch(
                    r"(?:issue8_|rag_|main_|owner_|native_|github_|context_)[a-z0-9_]{2,95}",
                    str(exc),
                )
            )
            else "issue8_native_dependency_unavailable"
        )
        print(json.dumps({
            "result": "ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED",
            "reason_code": code,
            "phase": _PHASE if _PHASE in _PHASES else "identity",
            "state_changed": False,
            "draft_pr_created": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(observed, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
