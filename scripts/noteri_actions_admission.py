"""Noteri-only Actions admission: inspect first, dispatch one fixed workflow.

Uses the existing local GitHub CLI identity; never exports credentials, registers
runners, changes labels, changes profiles, merges code or executes arbitrary SQL.
Run only through Session Launcher and Command Gateway.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
from datetime import datetime, timezone

import noteri_native_qualification as native
import noteri_qualification_receipt as receipts

OWNER = "ericson-j-santos"
REPOSITORY = OWNER + "/noteri-runtime"
RELATED = OWNER + "/reqsys-v2-enterprise-real"
REF = "fix/host-qualification-integration-20261019"
WORKFLOW = "noteri-control-plane-probe.yml"
LABELS = {"self-hosted", "windows", "x64", "noteri", "reqsys-dev"}
API_VERSION = "2026-03-10"
CONFIRM = "DISPATCH-NOTERI-QUALIFICATION-ONCE"
MAX_BYTES = 1024 * 1024


class Blocked(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise Blocked(reason)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GitHubRead:
    """No caller-supplied command/URL; fixed GitHub endpoint allowlist."""
    def __init__(self):
        binary = shutil.which("gh")
        require(bool(binary), "github_cli_missing")
        expected = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "GitHub CLI" / "gh.exe"
        require(Path(binary).resolve() == expected.resolve(), "github_cli_origin_unverified")
        native.read_regular(expected, 128 * 1024 * 1024)
        self.binary = str(expected)
        self.env = os.environ.copy()
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
                    "GH_CONFIG_DIR", "GH_DEBUG"):
            self.env.pop(key, None)
        self.env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1",
                        GIT_TERMINAL_PROMPT="0", GH_PAGER="")

    def call(self, endpoint: str, *, post: bool = False) -> dict:
        allowed = {
            "user",
            f"repos/{REPOSITORY}/actions/runners?per_page=100",
            f"repos/{RELATED}/actions/runners?per_page=100",
            f"repos/{REPOSITORY}/git/ref/heads/{REF}",
            f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}",
            f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/runs?per_page=100",
        }
        run_read = re.fullmatch(r"repos/" + re.escape(REPOSITORY) + r"/actions/runs/[1-9][0-9]*", endpoint)
        dispatch = f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/dispatches"
        require((post and endpoint == dispatch) or
                (not post and (endpoint in allowed or run_read)), "github_endpoint_not_allowed")
        args = [self.binary, "api", "--hostname", "github.com", "--method", "POST" if post else "GET",
                endpoint, "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: " + API_VERSION]
        if post:
            args += ["-f", "ref=" + REF]
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=35, check=False, shell=False, env=self.env)
        if p.returncode:
            match = re.search(r"HTTP (401|403|404|422|429|5[0-9]{2})", p.stderr)
            raise Blocked("github_http_" + match[1] if match else "github_cli_request_failed")
        require(len(p.stdout.encode()) <= MAX_BYTES, "github_response_limit")
        try:
            value = json.loads(p.stdout)
        except (ValueError, TypeError):
            raise Blocked("github_response_not_json") from None
        require(isinstance(value, dict), "github_response_shape")
        return value


def registry(api, repository: str) -> dict:
    require(repository in (REPOSITORY, RELATED), "repository_not_allowed")
    value = api.call(f"repos/{repository}/actions/runners?per_page=100")
    rows = value.get("runners")
    count = value.get("total_count")
    require(type(count) is int and isinstance(rows, list) and count == len(rows),
            "runner_registry_incomplete")
    selected = []
    for row in rows:
        require(isinstance(row, dict), "runner_record_invalid")
        labels = row.get("labels", [])
        require(isinstance(labels, list) and all(isinstance(x, dict) for x in labels),
                "runner_labels_invalid")
        names = [x.get("name") for x in labels]
        require(all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,100}", x)
                    for x in names), "runner_label_invalid")
        normalized = {x.casefold() for x in names}
        name = row.get("name", "")
        require(isinstance(name, str), "runner_name_invalid")
        if "noteri" not in name.casefold() and "noteri" not in normalized:
            continue
        require(re.fullmatch(r"[A-Za-z0-9_. -]{1,100}", name) is not None
                and type(row.get("id")) is int and row["id"] > 0
                and type(row.get("busy")) is bool, "runner_identity_invalid")
        selected.append({
            "id": row["id"], "name": name, "status": row.get("status"),
            "busy": row["busy"], "os": row.get("os"),
            "labels": sorted(names),
            "eligible": row.get("status") == "online" and row["busy"] is False
                        and str(row.get("os", "")).casefold() == "windows"
                        and LABELS <= normalized,
        })
    return {"repository": repository, "total_count": count, "noteri_runners": selected}


def inspect(api) -> dict:
    require(api.call("user").get("login") == OWNER, "github_account_mismatch")
    evidence = []
    for repo in (REPOSITORY, RELATED):
        try:
            evidence.append(registry(api, repo))
        except Blocked as exc:
            evidence.append({"repository": repo, "blocked": str(exc)})
    primary = evidence[0]
    candidates = [r for r in primary.get("noteri_runners", []) if r["eligible"]]
    return {"status": "observed", "host": "Noteri", "observed_at": utc_now(),
            "registries": evidence, "dispatch_candidate_count": len(candidates),
            "dispatch_eligible": len(candidates) == 1,
            "actions_qualified": False, "hml_verified": False,
            "registration_changed": False, "credentials_exported": False}


def guard(expected_sha: str, correlation_id: str) -> None:
    require(os.name == "nt" and socket.gethostname().casefold() == "noteri", "noteri_required")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "source_sha_invalid")
    require(re.fullmatch(r"[A-Za-z0-9_.-]{8,100}", correlation_id) is not None, "correlation_invalid")
    native.source_head(expected_sha)


def readback_run(api, run_id: int, expected_sha: str) -> dict:
    observed = api.call(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(observed.get("id") == run_id and observed.get("head_sha") == expected_sha
            and observed.get("event") == "workflow_dispatch"
            and observed.get("path") == ".github/workflows/" + WORKFLOW, "dispatch_readback_mismatch")
    return observed


def dispatch_once(api, expected_sha: str, correlation_id: str, state_dir: Path, confirm: str) -> dict:
    require(confirm == CONFIRM, "dispatch_confirmation_required")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "source_sha_invalid")
    require(re.fullmatch(r"[A-Za-z0-9_.-]{8,100}", correlation_id) is not None, "correlation_invalid")
    for p in (state_dir, *state_dir.parents):
        if p.exists() or p.is_symlink():
            info = p.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, "st_file_attributes", 0) & 0x400, "state_reparse")
    state_dir.mkdir(parents=True, exist_ok=True)
    lock = state_dir / "dispatch.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise Blocked("dispatch_lock_held") from None
    os.close(fd)
    checkpoint = state_dir / (correlation_id + ".json")
    try:
        if checkpoint.exists():
            old = native.read_json(checkpoint)
            require(old.get("source_sha") == expected_sha
                    and old.get("correlation_id") == correlation_id, "dispatch_checkpoint_binding")
            require(old.get("state") == "submitted" and type(old.get("run_id")) is int,
                    "submission_unresolved_no_retry")
            run_id = old["run_id"]
            require(run_id > 0 and old.get("repository") == REPOSITORY
                    and old.get("workflow") == WORKFLOW and old.get("ref") == REF
                    and old.get("actions_qualified") is False and old.get("hml_verified") is False
                    and old.get("run_url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
                    "dispatch_checkpoint_shape")
            observed = readback_run(api, run_id, expected_sha)
            result = {key: old[key] for key in (
                "state", "source_sha", "correlation_id", "repository", "workflow",
                "ref", "created_at", "actions_qualified", "hml_verified", "run_id", "run_url")}
            return {**result, "run_status": observed.get("status"), "readback_verified": True,
                    "replayed": True, "submitted_by_this_call": False}

        profile = native.profile()
        require(profile.get("verified") is True and profile.get("profile") == "NORMAL", "normal_required")
        observation = inspect(api)
        require(observation["dispatch_eligible"], "noteri_runner_not_eligible")
        ref = api.call(f"repos/{REPOSITORY}/git/ref/heads/{REF}")
        require(ref.get("object", {}).get("sha") == expected_sha, "dispatch_ref_changed")
        workflow = api.call(f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}")
        require(workflow.get("state") == "active"
                and workflow.get("path") == ".github/workflows/" + WORKFLOW, "workflow_not_approved")
        recent = api.call(f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/runs?per_page=100")
        runs = recent.get("workflow_runs")
        require(isinstance(runs, list) and type(recent.get("total_count")) is int
                and recent["total_count"] == len(runs) and len(runs) <= 100, "runs_incomplete")
        # Do not create another queue behind an unresolved qualification attempt.
        require(all(isinstance(r, dict) and r.get("status") == "completed" for r in runs),
                "qualification_already_active")
        intent = {"state": "submission_intent", "source_sha": expected_sha,
                  "correlation_id": correlation_id, "repository": REPOSITORY,
                  "workflow": WORKFLOW, "ref": REF, "created_at": utc_now(),
                  "actions_qualified": False, "hml_verified": False}
        receipts.write_atomic(checkpoint, intent)  # Persist BEFORE the only POST.
        response = api.call(f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/dispatches", post=True)
        run_id = response.get("workflow_run_id")
        require(type(run_id) is int and run_id > 0
                and response.get("html_url") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
                and response.get("run_url") == f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}",
                "dispatch_receipt_invalid_no_retry")
        submitted = {**intent, "state": "submitted", "run_id": run_id,
                     "run_url": response["html_url"]}
        receipts.write_atomic(checkpoint, submitted)
        observed = readback_run(api, run_id, expected_sha)
        return {**submitted, "run_status": observed.get("status"), "readback_verified": True,
                "replayed": False, "submitted_by_this_call": True}
    finally:
        lock.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["inspect", "dispatch"])
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--correlation-id", required=True)
    parser.add_argument("--confirm")
    args = parser.parse_args()
    try:
        guard(args.expected_head, args.correlation_id)
        api = GitHubRead()
        if args.mode == "inspect":
            result = inspect(api)
            result.update(source_sha=args.expected_head, correlation_id=args.correlation_id)
        else:
            local = os.environ.get("LOCALAPPDATA")
            require(bool(local), "localappdata_missing")
            result = dispatch_once(api, args.expected_head, args.correlation_id,
                                   Path(local) / "ReqSys" / "NoteriQualificationDispatch", args.confirm)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "blocked",
                          "code": str(exc) if isinstance(exc, Blocked) else type(exc).__name__,
                          "actions_qualified": False, "hml_verified": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
