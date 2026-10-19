"""Bind Noteri native observations to a governed Actions job and independent artifact."""
from __future__ import annotations
import argparse
import hashlib
import importlib
import io
import json
import os
import re
import sys
import stat
import tempfile
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import noteri_native_qualification as native

REPO = native.REPOSITORY
JOB_NAME = "Qualify Noteri through Command Gateway"
STEP_NAME = "Verify governed host qualification"
API = "https://api.github.com/repos/" + REPO
LIMIT = 1024 * 1024
class Blocked(ValueError):
    pass

def require(condition: bool, code: str) -> None:
    if not condition:
        raise Blocked(code)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def fresh(stamp: str) -> bool:
    try:
        dt = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        return dt.tzinfo is not None and 0 <= (datetime.now(timezone.utc)-dt).total_seconds() <= 300
    except (AttributeError, ValueError, OverflowError):
        return False

def write_atomic(path: Path, data: dict) -> None:
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "output_reparse")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True, ensure_ascii=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def context() -> tuple[str, int, int, str]:
    e = os.environ
    require(e.get("GITHUB_ACTIONS") == "true" and e.get("GITHUB_REPOSITORY") == REPO
            and e.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and e.get("GITHUB_ACTOR") == "ericson-j-santos", "actions_scope")
    sha = e.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "actions_sha")
    run, attempt = e.get("GITHUB_RUN_ID", ""), e.get("GITHUB_RUN_ATTEMPT", "")
    require(run.isdecimal() and attempt.isdecimal() and int(run)>0 and int(attempt)>0, "actions_identity")
    correlation = f"noteri-qualification-{run}-{attempt}"
    return sha, int(run), int(attempt), correlation

def rules_module(root: Path, expected_sha: str):
    require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "rules_sha")
    p = native.subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=15, check=False, shell=False)
    require(p.returncode == 0 and p.stdout.strip() == expected_sha, "rules_checkout_mismatch")
    status = native.subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, timeout=15, check=False, shell=False)
    require(status.returncode == 0 and not status.stdout.strip(), "rules_checkout_dirty")
    sys.path.insert(0, str(root / "scripts"))
    module = importlib.import_module("command_gateway")
    require(Path(module.__file__).resolve() == (root/"scripts/command_gateway.py").resolve(),
            "rules_module_origin")
    return module

def produce(rules_root: Path, rules_sha: str, session_file: Path, output: Path) -> dict:
    sha, run, attempt, correlation = context()
    session = native.read_json(session_file)
    require(session.get("result") == "SESSION_LAUNCH_OK" and session.get("state_validated") is True
            and session.get("head") == sha and session.get("host") == native.HOST
            and session.get("correlation_id") == correlation, "session_binding")
    require(fresh(session.get("timestamp", "")), "session_stale")
    cg = rules_module(rules_root, rules_sha)
    policy = cg.load_policy(rules_root / "config" / "command-gateway.policy.json")
    require(policy.get("rules_version") == session.get("rules_version"), "rules_version_mismatch")
    cwd = Path.cwd()
    require(cwd.resolve() == Path(session.get("target_path", "")).resolve(), "session_worktree")
    cg.enforce_session(policy, session.get("session_id"), cwd, 1)
    state = cg.git_state(cwd, True, policy)
    require(state is not None and state.head == sha and state.status_count == 0, "worktree_not_clean")
    observation = native.collect(sha, correlation)
    require(observation.get("rollback", {}).get("state_verified") is not False, "runtime_state_unreconciled")
    profile = observation["operating_profile"]
    if profile.get("verified") is not True or profile.get("profile") != "NORMAL":
        write_atomic(output, {"status": "blocked", "code": "profile_unqualified",
                              "observation": observation, "hml_verified": False})
        raise Blocked("profile_unqualified")
    record = {
        "schema_version": "1", "host": native.HOST, "repository": REPO,
        "source_sha": sha, "rules_sha": rules_sha, "run_id": run, "run_attempt": attempt,
        "runner_name": os.environ.get("RUNNER_NAME", ""), "correlation_id": correlation,
        "profile": profile["profile"], "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_result": session["result"], "session_id": session["session_id"],
        "snapshot_sha256": session["snapshot_sha256"], "state_validated": True,
        "gateway_ok": True, "auth_valid": True, "independent_effect_verified": False,
        "capabilities": {"platform": "Windows", "native_inventory": "observed"},
        "observation": observation, "hml_verified": False,
        "worktree_status_count": state.status_count,
    }
    require(bool(record["runner_name"]), "runner_name_missing")
    # Independent hosted readback, not this producer, confirms the transport.
    write_atomic(output, record)
    return {"receipt_written": True, "hml_verified": False}

def local_readback(rules_root: Path, rules_sha: str, session_file: Path, output: Path) -> dict:
    """A second Gateway process reopens the receipt and rereads native host state."""
    sha, run, attempt, correlation = context()
    receipt = native.read_json(output)
    session = native.read_json(session_file)
    require(receipt.get("source_sha") == sha and receipt.get("rules_sha") == rules_sha
            and receipt.get("run_id") == run and receipt.get("run_attempt") == attempt
            and receipt.get("correlation_id") == correlation, "local_receipt_binding")
    require(fresh(receipt.get("generated_at", "")), "local_receipt_stale")
    cg = rules_module(rules_root, rules_sha)
    policy = cg.load_policy(rules_root/"config/command-gateway.policy.json")
    cwd = Path.cwd()
    require(cwd.resolve() == Path(session.get("target_path", "")).resolve()
            and session.get("session_id") == receipt.get("session_id")
            and session.get("snapshot_sha256") == receipt.get("snapshot_sha256"), "local_session_binding")
    cg.enforce_session(policy, receipt.get("session_id"), cwd, 1)
    state = cg.git_state(cwd, True, policy)
    require(state is not None and state.head == sha and state.status_count == 0, "local_state_changed")
    observed = native.collect(sha, correlation)
    prior = dict(receipt.get("observation", {}))
    current = dict(observed)
    prior.pop("generated_at", None)
    current.pop("generated_at", None)
    require(prior == current and observed["operating_profile"].get("profile") == "NORMAL"
            and observed["operating_profile"].get("verified") is True, "local_readback_changed")
    receipt["independent_effect_verified"] = True
    receipt["local_readback_sha256"] = digest(json.dumps(observed, sort_keys=True).encode())
    receipt["local_readback_at"] = observed["generated_at"]
    write_atomic(output, receipt)
    return {"local_readback_verified": True, "hml_verified": False}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def api_bytes(path: str, *, archive: bool = False) -> bytes:
    require(re.fullmatch(r"/actions/[A-Za-z0-9_/?=&.-]+", path) is not None, "api_path")
    token = os.environ.get("GITHUB_TOKEN", "")
    require(bool(token), "actions_read_token_missing")
    request = urllib.request.Request(API+path, headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer "+token})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as exc:
        if not archive or exc.code != 302:
            raise Blocked("github_read_failed") from None
        from urllib.parse import urlsplit
        target = exc.headers.get("Location", "")
        parts = urlsplit(target)
        require(parts.scheme == "https" and not parts.username and not parts.password
                and bool(parts.hostname) and parts.hostname.endswith(".blob.core.windows.net"), "artifact_redirect")
        # Deliberately DO NOT forward Authorization to blob storage.
        response = opener.open(urllib.request.Request(target), timeout=20)
    with response:
        data = response.read(LIMIT+1)
    require(len(data) <= LIMIT, "response_limit")
    return data

def api_json(path: str) -> dict:
    data = json.loads(api_bytes(path))
    require(isinstance(data, dict), "api_shape")
    return data

def validate_bundle(job: dict, artifact: dict, archive: bytes, sha: str,
                    rules_sha: str, run: int, attempt: int) -> dict:
    require(isinstance(job, dict) and isinstance(artifact, dict), "metadata_shape")
    require(type(run) is int and type(attempt) is int, "execution_identity_type")
    require(job.get("status") == "completed" and job.get("conclusion") == "success"
            and job.get("run_id") == run and job.get("run_attempt") == attempt
            and job.get("head_sha") == sha and job.get("name") == JOB_NAME, "job_binding")
    require(isinstance(job.get("labels"), list) and isinstance(job.get("steps"), list),
            "job_lists_invalid")
    require(type(job.get("id")) is int and job["id"] > 0
            and type(job.get("runner_id")) is int and job["runner_id"] > 0
            and "self-hosted" in job.get("labels", []), "runner_not_physical")
    require(any(s.get("name") == STEP_NAME and s.get("status") == "completed"
                and s.get("conclusion") == "success" for s in job.get("steps", [])
                if isinstance(s, dict)), "qualification_not_executed")
    require(fresh(job.get("completed_at", "")), "job_expired")
    require(isinstance(artifact.get("workflow_run"), dict), "artifact_run_missing")
    require(artifact.get("expired") is False and artifact.get("digest") == "sha256:"+digest(archive)
            and artifact.get("name") == f"noteri-qualification-{run}-{attempt}"
            and artifact.get("workflow_run", {}).get("head_sha") == sha
            and artifact.get("workflow_run", {}).get("id") == run, "artifact_binding")
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        infos = z.infolist()
        require(len(infos) == 1 and infos[0].filename == "receipt.json"
                and infos[0].file_size <= LIMIT, "archive_shape")
        receipt = json.loads(z.read(infos[0]))
    require(isinstance(receipt, dict), "receipt_shape")
    binding = {"host": native.HOST, "repository": REPO, "source_sha": sha,
               "rules_sha": rules_sha, "run_id": run, "run_attempt": attempt,
               "runner_name": job.get("runner_name"), "profile": "NORMAL",
               "correlation_id": f"noteri-qualification-{run}-{attempt}",
               "session_result": "SESSION_LAUNCH_OK"}
    require(all(type(receipt.get(k)) is type(v) and receipt.get(k) == v for k,v in binding.items()),
            "receipt_binding")
    require(fresh(receipt.get("generated_at", "")), "receipt_expired")
    require(all(receipt.get(k) is True for k in ("state_validated", "gateway_ok", "auth_valid")),
            "session_not_verified")
    require(re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("snapshot_sha256", ""))) is not None,
            "snapshot_invalid")
    require(receipt.get("independent_effect_verified") is True
            and fresh(receipt.get("local_readback_at", ""))
            and re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("local_readback_sha256", ""))) is not None,
            "physical_readback_missing")
    require(type(receipt.get("worktree_status_count")) is int
            and receipt["worktree_status_count"] == 0, "receipt_worktree_unclean")
    require(receipt.get("hml_verified") is False
            and receipt.get("capabilities") == {"platform": "Windows", "native_inventory": "observed"},
            "unsupported_capability_claim")
    observation = receipt.get("observation", {})
    require(isinstance(observation, dict), "observation_shape")
    require(observation.get("status") == "observed" and observation.get("host") == native.HOST
            and observation.get("source_sha") == sha and observation.get("correlation_id") == binding["correlation_id"]
            and observation.get("hml_verified") is False and observation.get("mutations_executed") is False
            and observation.get("production_touched") is False and observation.get("secrets_read") is False,
            "observation_binding")
    require(observation.get("operating_profile", {}).get("verified") is True
            and observation["operating_profile"].get("profile") == "NORMAL",
            "profile_not_verified")
    require(observation.get("rollback", {}).get("state_verified") is not False, "runtime_unreconciled")
    receipt = dict(receipt)
    receipt.update(job_id=job["id"], runner_id=job["runner_id"], independent_effect_verified=True)
    return receipt

def verify(rules_root: Path, rules_sha: str, output: Path) -> dict:
    blocked = {"ready": False, "hml_verified": False, "decision_only": True}
    try:
        sha, run, attempt, correlation = context()
        blocked["correlation_id"] = correlation
        rows = api_json(f"/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100")
        jobs = rows.get("jobs", [])
        require(rows.get("total_count") == len(jobs), "jobs_incomplete")
        selected = [j for j in jobs if j.get("name") == JOB_NAME]
        require(len(selected) == 1, "job_ambiguous")
        job = selected[0]
        require(job.get("status") == "completed" and job.get("conclusion") == "success", "native_job_failed")
        assets = api_json(f"/actions/runs/{run}/artifacts?per_page=100")
        require(assets.get("total_count") == len(assets.get("artifacts", [])), "artifacts_incomplete")
        matching = [a for a in assets["artifacts"] if a.get("name") == f"noteri-qualification-{run}-{attempt}"]
        require(len(matching) == 1, "artifact_ambiguous")
        artifact = matching[0]
        archive = api_bytes(f"/actions/artifacts/{int(artifact['id'])}/zip", archive=True)
        receipt = validate_bundle(job, artifact, archive, sha, rules_sha, run, attempt)
        reread = api_json(f"/actions/jobs/{job['id']}")
        stable_fields = ("id", "run_id", "run_attempt", "runner_id", "runner_name", "head_sha",
                         "status", "conclusion", "name", "completed_at", "steps", "labels", "html_url")
        require(all(reread.get(k) == job.get(k) for k in stable_fields), "job_changed_during_readback")
        proof = {"schema_version": "1", "source": "github_api_and_gateway_receipt",
                 "repository": REPO, "observed_at": datetime.now(timezone.utc).isoformat(),
                 "independent_readback_verified": True, "artifact_sha256": digest(archive),
                 "readback_sha256": digest(json.dumps(reread, sort_keys=True).encode()),
                 "job": reread, "receipt": receipt}
        rules_module(rules_root, rules_sha)
        selector = importlib.import_module("dual_host_preflight")
        candidate = {"name": native.HOST, "transport": "github_actions", "transport_evidence": proof,
                     "execution_repository": REPO, "expected_source_sha": sha,
                     "runner_name": job["runner_name"], "profile": "NORMAL",
                     "rules_sha": rules_sha, "auth_valid": True, "gateway_ok": True,
                     "session_launch_ok": True, "state_validated": True,
                     "status_count": receipt["worktree_status_count"], "reserved_worktrees": []}
        result = selector.evaluate({"required_rules_sha": rules_sha, "correlation_id": correlation,
            "requested_workload": "development",
            "required_capabilities": {"platform": "Windows", "native_inventory": "observed"},
            "hosts": [candidate, {"name": "DESKTOP-PDQK954", "controller_online": False}]})
        require(result.get("selected_host") == native.HOST and result.get("ready") is True,
                "selector_rejected")
        write_atomic(output, result)
        return result
    except Exception as exc:
        blocked["code"] = str(exc) if isinstance(exc, Blocked) else type(exc).__name__
        write_atomic(output, blocked)  # Never persist an earlier ready=true result.
        raise

def launch(rules_root: Path, rules_sha: str) -> int:
    """Bootstrap once; all subsequent technical execution is through the Gateway."""
    sha, run, attempt, correlation = context()
    require(os.name == "nt" and native.socket.gethostname() == native.HOST, "noteri_required")
    rules_root = rules_root.resolve()
    cg = rules_module(rules_root, rules_sha)
    policy_path = rules_root / "config" / "command-gateway.policy.json"
    branch = os.environ.get("GITHUB_REF_NAME", "")
    require(re.fullmatch(r"[A-Za-z0-9_.\-/]+", branch) is not None
            and ".." not in branch, "branch_invalid")
    session_id = f"noteri-qual-{run}-{attempt}"
    command = [sys.executable, "-B", str(rules_root/"scripts/session_launcher.py"),
        "--policy", str(policy_path), "--repo", str(Path.cwd()),
        "--session-id", session_id, "--correlation-id", correlation,
        "--expected-head", sha, "--sync-ref", "origin/"+branch,
        "--require-runner-version-preflight"]
    process = native.subprocess.run(command, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=150, check=False, shell=False)
    require(process.returncode == 0, "session_launch_failed")
    session = json.loads(process.stdout.strip().splitlines()[-1])
    require(session.get("result") == "SESSION_LAUNCH_OK" and session.get("head") == sha
            and session.get("state_validated") is True and session.get("host") == native.HOST,
            "session_not_qualified")
    target = Path(session["target_path"])
    policy = cg.load_policy(policy_path)
    cg.enforce_session(policy, session_id, target, 1)
    evidence_dir = target / ".tmp" / "noteri-qualification"
    session_file = evidence_dir / "session.json"
    output = evidence_dir / "receipt.json"
    write_atomic(session_file, session)  # Bootstrap receipt, not a task command.
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write("receipt_path="+str(output)+"\n")
    print(json.dumps(session, ensure_ascii=True, sort_keys=True))
    args = [sys.executable, "-B", "scripts/noteri_qualification_receipt.py", "produce",
        "--rules-root", str(rules_root), "--rules-sha", rules_sha,
        "--session-file", str(session_file), "--output", str(output)]
    for mode in ("produce", "local-readback"):
        args[3] = mode
        code = cg.execute(cwd=target, policy=policy, args=args, risk=1, timeout=60,
            expected_head=sha, allow_dirty=False, allow_head_change=False,
            correlation_id=correlation, session_id=session_id)
        if code != 0:
            return code
    return 0

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["launch", "produce", "local-readback", "verify"])
    p.add_argument("--rules-root", required=True, type=Path)
    p.add_argument("--rules-sha", required=True)
    p.add_argument("--session-file", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    try:
        if a.mode == "launch":
            return launch(a.rules_root, a.rules_sha)
        require(a.output is not None, "output_required")
        if a.mode in ("produce", "local-readback"):
            require(a.session_file is not None, "session_file_required")
            handler = produce if a.mode == "produce" else local_readback
            result = handler(a.rules_root, a.rules_sha, a.session_file, a.output)
        else:
            result = verify(a.rules_root, a.rules_sha, a.output)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ready": False, "hml_verified": False,
            "code": str(exc) if isinstance(exc, Blocked) else type(exc).__name__}))
        return 2
if __name__ == "__main__":
    raise SystemExit(main())
