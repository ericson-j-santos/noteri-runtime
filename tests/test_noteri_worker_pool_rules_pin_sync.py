"""Pin repair, drift detection and typed candidate-only automation."""
from __future__ import annotations

import io
import json
import subprocess
from email.message import Message
from pathlib import Path

import pytest

from scripts import noteri_worker_pool_rules_pin_sync as pin

CURRENT_RULES = "58dcd4200f412a866278027ba9e433439a03f3b3"
OLD_RULES = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"


def source_for(sha=OLD_RULES) -> str:
    return (
        "SOURCE_SHA = \"21fd68dec6f0da92b3e7da201463401ac5429d64\"\n"
        + 'RULES_SHA = "' + sha + '"\n'
        + "def use():\n    return RULES_SHA\n"
    )


def test_checked_in_launcher_matches_authoritative_rules_sha_at_change():
    runner = (Path(__file__).resolve().parents[1] /
              "scripts/noteri_worker_pool_api_runner.py").read_text(encoding="utf-8")
    assert pin.pinned_sha(runner) == CURRENT_RULES
    assert "CODEX_WORKER_POOL_EXPECTED_RULES_SHA" in runner
    assert pin.candidate_source(runner, CURRENT_RULES) == runner


def test_minimal_candidate_changes_only_single_literal_and_is_idempotent():
    original = source_for()
    changed = pin.candidate_source(original, CURRENT_RULES)
    assert changed == original.replace(OLD_RULES, CURRENT_RULES)
    assert pin.pinned_sha(changed) == CURRENT_RULES
    assert pin.candidate_source(changed, CURRENT_RULES) == changed
    assert pin.candidate_source(changed, OLD_RULES) == original


@pytest.mark.parametrize("content", [
    "",
    "RULES_SHA = get_value()\n",
    'RULES_SHA = "' + OLD_RULES + '"\nRULES_SHA = "' + OLD_RULES + '"\n',
    'RULES_SHA: str = "' + OLD_RULES + '"\n',
    'RULES_SHA = "' + OLD_RULES + '"  # trailing modification\n',
    'RULES_SHA = "' + OLD_RULES + '"\nRULES_SHA += "x"\n',
])
def test_untrusted_source_fails_closed(content):
    with pytest.raises(pin.SyncBlocked):
        pin.candidate_source(content, CURRENT_RULES)


@pytest.mark.parametrize("value", ["", "HEAD", "z"*40, "a"*39, "A"*40])
def test_canonical_sha_must_be_exact_lowercase_sha40(value):
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_RULES_SHA"):
        pin.verified_sha(value)


class FakeResponse(io.BytesIO):
    status = 200

    def __init__(self, body: bytes, *, origin=pin.RULES_URL, media="application/json"):
        super().__init__(body)
        self.origin = origin
        self.headers = Message()
        self.headers["Content-Type"] = media

    def geturl(self):
        return self.origin


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requested = None

    def open(self, request, timeout):
        self.requested = request.full_url
        assert timeout == 8
        return self.response


def test_read_authoritative_branch_from_fixed_api_without_auth():
    opener = FakeOpener(FakeResponse(
        json.dumps({"name": "main", "commit": {"sha": CURRENT_RULES}}).encode()
    ))
    assert pin.canonical_rules_sha(opener=opener) == CURRENT_RULES
    assert opener.requested == pin.RULES_URL


@pytest.mark.parametrize("response", [
    FakeResponse(b'{"name":"other","commit":{"sha":"' + CURRENT_RULES.encode() + b'"}}'),
    FakeResponse(b'{"name":"main","commit":{"sha":"invalid"}}'),
    FakeResponse(b'{"name":"main","commit":{"sha":"' + CURRENT_RULES.encode() + b'"}}',
                 origin="https://evil.test/data"),
    FakeResponse(b'{"name":"main","commit":{"sha":"' + CURRENT_RULES.encode() + b'"}}',
                 media="text/html"),
    FakeResponse(b'X' * 16385),
])
def test_canonical_fetch_rejects_wrong_origin_schema_type_or_size(response):
    with pytest.raises(pin.SyncBlocked):
        pin.canonical_rules_sha(opener=FakeOpener(response))


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True,
        check=True, timeout=15,
    )
    return proc.stdout.strip()


def git_fixture(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "candidate"
    repo.mkdir()
    _git(repo, "init", "-b", "fix/issue42-rules-sha-drift")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "Test Fixture")
    _git(repo, "remote", "add", "origin",
         "https://github.com/ericson-j-santos/noteri-runtime.git")
    runner = repo / pin.RUNNER_REL
    runner.parent.mkdir(parents=True)
    runner.write_text(source_for(), encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "synthetic initial source")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_plan_is_read_only_and_prepare_updates_only_candidate(tmp_path):
    repo, head = git_fixture(tmp_path)
    runner = repo / pin.RUNNER_REL
    initial = runner.read_bytes()
    planned = pin.sync(repo=repo, canonical=CURRENT_RULES, mode="plan")
    assert planned["result"] == "RULES_SHA_DRIFT"
    assert planned["candidate_path"] == pin.RUNNER_REL.as_posix()
    assert runner.read_bytes() == initial
    assert _git(repo, "status", "--porcelain") == ""
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_CONFIRM"):
        pin.sync(repo=repo, canonical=CURRENT_RULES, mode="prepare",
                 expected_head=head)
    result = pin.sync(
        repo=repo, canonical=CURRENT_RULES, mode="prepare",
        expected_head=head, confirm=pin.CONFIRM,
    )
    assert result["result"] == "CANDIDATE_PREPARED"
    assert result["installed_runner_changed"] is False
    assert result["branch_merged"] is False and result["deployed"] is False
    assert pin.pinned_sha(runner.read_text(encoding="utf-8")) == CURRENT_RULES
    assert _git(repo, "rev-parse", "HEAD") == head
    assert _git(repo, "status", "--porcelain") == "M scripts/noteri_worker_pool_api_runner.py"
    assert pin.sync(repo=repo, canonical=CURRENT_RULES, mode="plan")["result"] == "RULES_SHA_ALIGNED"


def test_wrong_expected_head_or_dirty_worktree_fails_before_write(tmp_path):
    repo, head = git_fixture(tmp_path)
    runner = repo / pin.RUNNER_REL
    original = runner.read_bytes()
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_WORKTREE_IDENTITY"):
        pin.sync(repo=repo, canonical=CURRENT_RULES, mode="prepare",
                 expected_head="b" * 40, confirm=pin.CONFIRM)
    assert runner.read_bytes() == original
    (repo / "outside.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_WORKTREE_DIRTY"):
        pin.sync(repo=repo, canonical=CURRENT_RULES, mode="prepare",
                 expected_head=head, confirm=pin.CONFIRM)
    assert runner.read_bytes() == original


def test_wrong_remote_and_protected_branch_are_refused(tmp_path):
    repo, head = git_fixture(tmp_path)
    _git(repo, "remote", "set-url", "origin", "https://github.com/evil/repo")
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_WORKTREE_IDENTITY"):
        pin.candidate_preflight(repo, head)
    _git(repo, "remote", "set-url", "origin",
         "https://github.com/ericson-j-santos/noteri-runtime")
    _git(repo, "branch", "-m", "main")
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_WORKTREE_IDENTITY"):
        pin.candidate_preflight(repo, head)


def test_drift_probe_never_touches_installed_runner(tmp_path):
    repo, _ = git_fixture(tmp_path)
    local = tmp_path / "installed"
    local.mkdir()
    active = local / "noteri_worker_pool_api_runner.py"
    active.write_text(source_for(), encoding="utf-8")
    before = active.read_bytes()
    plan = pin.sync(repo=repo, canonical=CURRENT_RULES, mode="plan")
    assert plan["change_required"] is True
    assert active.read_bytes() == before
    source = (Path(__file__).resolve().parents[1] /
              "scripts/noteri_worker_pool_rules_pin_sync.py").read_text(encoding="utf-8")
    assert "TaskScheduler" not in source
    assert "uvicorn.run(" not in source
    assert ".github/workflows" not in source
    assert "subprocess.Popen" not in source



def test_ci_reuses_existing_tests_job_without_new_paid_runner_or_trigger():
    text = (Path(__file__).resolve().parents[1] / ".github" / "workflows" /
            "ci.yml").read_text(encoding="utf-8")
    assert text.count(
        "python -B -m scripts.noteri_worker_pool_rules_pin_sync --mode check"
    ) == 1
    assert text.index("Run tests") < text.index(
        "Check canonical Worker Pool rules SHA (read-only, no install)"
    )
    assert "runs-on: ubuntu-latest" in text
    assert "workflow_dispatch:" not in text
    assert "schedule:" not in text


def test_check_mode_exit_code_fails_on_future_drift_without_writing(monkeypatch, capsys):
    import sys
    from scripts import noteri_worker_pool_rules_pin_sync as module

    target = Path(module.__file__).resolve().parents[1] / module.RUNNER_REL
    before = target.read_bytes()
    monkeypatch.setattr(module, "canonical_rules_sha", lambda: OLD_RULES)
    monkeypatch.setattr(sys, "argv", ["rules-pin-sync", "--mode", "check"])
    assert module.main() == 2
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["result"] == "RULES_SHA_DRIFT"
    assert outcome["change_required"] is True
    assert outcome["service_changed"] is False
    assert target.read_bytes() == before


def test_check_mode_success_on_canonical_and_no_file_change(monkeypatch, capsys):
    import sys
    from scripts import noteri_worker_pool_rules_pin_sync as module

    target = Path(module.__file__).resolve().parents[1] / module.RUNNER_REL
    before = target.read_bytes()
    monkeypatch.setattr(module, "canonical_rules_sha", lambda: CURRENT_RULES)
    monkeypatch.setattr(sys, "argv", ["rules-pin-sync", "--mode", "check"])
    assert module.main() == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["result"] == "RULES_SHA_ALIGNED"
    assert outcome["change_required"] is False
    assert target.read_bytes() == before



def test_public_git_fallback_reads_only_exact_authoritative_ref(monkeypatch):
    observed = []
    def fake_run(argv, **opts):
        observed.append((argv, opts))
        return subprocess.CompletedProcess(
            argv, 0, stdout=CURRENT_RULES + "\trefs/heads/main\n", stderr=""
        )
    monkeypatch.setattr(pin.subprocess, "run", fake_run)
    assert pin.canonical_rules_sha_git() == CURRENT_RULES
    assert len(observed) == 1
    argv, opts = observed[0]
    assert argv[0] == "git" and argv[1:3] == ["-c", "http.followRedirects=false"]
    assert argv[3:5] == ["ls-remote", "--exit-code"]
    assert argv[5] == pin.RULES_GIT_REMOTE
    assert argv[6] == "refs/heads/main"
    assert opts["timeout"] == 12
    assert opts["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert opts["env"]["GIT_ASKPASS"] == pin.os.devnull


@pytest.mark.parametrize("output,returncode", [
    ("", 0),
    (CURRENT_RULES + "\trefs/heads/dev\n", 0),
    ("z" * 40 + "\trefs/heads/main\n", 0),
    (CURRENT_RULES + " refs/heads/main\n", 0),
    (CURRENT_RULES + "\trefs/heads/main\n" * 2, 0),
    (CURRENT_RULES + "\trefs/heads/main\n", 1),
])
def test_git_canonical_invalid_ref_fails_closed(monkeypatch, output, returncode):
    monkeypatch.setattr(pin.subprocess, "run", lambda argv, **opts:
                        subprocess.CompletedProcess(
                            argv, returncode, stdout=output, stderr="private-unprinted"
                        ))
    with pytest.raises(pin.SyncBlocked):
        pin.canonical_rules_sha_git()


def test_git_canonical_unavailable_fails_closed(monkeypatch):
    def unavailable(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=12)
    monkeypatch.setattr(pin.subprocess, "run", unavailable)
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_CANONICAL_UNAVAILABLE"):
        pin.canonical_rules_sha_git()


def test_live_fallback_only_if_rest_unavailable(monkeypatch):
    calls = []
    def no_api():
        calls.append("rest")
        raise pin.SyncBlocked("BLOCKED_CANONICAL_UNAVAILABLE")
    def git_ok():
        calls.append("git")
        return CURRENT_RULES
    monkeypatch.setattr(pin, "canonical_rules_sha", no_api)
    monkeypatch.setattr(pin, "canonical_rules_sha_git", git_ok)
    assert pin.current_rules_sha() == CURRENT_RULES
    assert calls == ["rest", "git"]

    calls.clear()
    monkeypatch.setattr(pin, "canonical_rules_sha",
                        lambda: (_ for _ in ()).throw(
                            pin.SyncBlocked("BLOCKED_CANONICAL_ORIGIN")))
    with pytest.raises(pin.SyncBlocked, match="BLOCKED_CANONICAL_ORIGIN"):
        pin.current_rules_sha()
    assert calls == []  # A malformed response never becomes a fallback.

    calls.clear()
    monkeypatch.setattr(pin, "canonical_rules_sha", lambda: CURRENT_RULES)
    assert pin.current_rules_sha() == CURRENT_RULES
    assert calls == []  # No needless second request.
