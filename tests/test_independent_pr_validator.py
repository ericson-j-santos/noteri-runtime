import copy
import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "independent_pr_validator.py"
SPEC = importlib.util.spec_from_file_location("independent_pr_validator", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def valid_evidence():
    sha = "a" * 40
    main = "b" * 40
    return {
        "schema_version": 1,
        "source": "github_workflow_run_and_api",
        "repository": "ericson-j-santos/noteri-runtime",
        "validator_identity": "github-actions[bot]",
        "main_sha": main,
        "workflow_run": {"id": 123, "name": "CI", "event": "pull_request", "status": "completed", "conclusion": "success", "head_sha": sha},
        "pull_request": {"number": 87, "state": "open", "author": "maintainer", "base_ref": "main", "base_sha": main, "head_sha": sha},
        "jobs": [
            {"name": name, "head_sha": sha, "status": "completed", "conclusion": "success", "steps": [{"name": "test", "status": "completed", "conclusion": "success"}]}
            for name in MODULE.REQUIRED_JOBS
        ],
        "unresolved_review_threads": 0,
        "changed_files": ["scripts/example.py"],
        "diff_digest": "c" * 64,
    }


def test_positive_and_idempotent():
    evidence = valid_evidence()
    first = MODULE.validate(evidence, evidence["repository"])
    second = MODULE.validate(copy.deepcopy(evidence), evidence["repository"])
    assert first == second
    assert first["verdict"] == "INDEPENDENT_VALIDATOR_PASSED"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda e: e["pull_request"].update(head_sha="d" * 40), "avançou"),
        (lambda e: e["pull_request"].update(base_sha="d" * 40), "desatualizada"),
        (lambda e: e["pull_request"].update(author="github-actions[bot]"), "autor"),
        (lambda e: e["jobs"].pop(), "job obrigatório ausente"),
        (lambda e: e["jobs"][0]["steps"][0].update(conclusion="skipped"), "step não passou"),
        (lambda e: e.update(unresolved_review_threads=1), "thread"),
        (lambda e: e.update(changed_files=[]), "diff vazio"),
        (lambda e: e.update(diff_digest="invalid"), "digest"),
    ],
)
def test_fail_closed(mutate, expected):
    evidence = valid_evidence()
    mutate(evidence)
    with pytest.raises(MODULE.ValidationError, match=expected):
        MODULE.validate(evidence, evidence["repository"])


def test_workflow_is_read_only_sha_bound_and_has_independent_readback():
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "independent-pr-validator.yml").read_text(encoding="utf-8")
    assert "workflow_run:" in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "pull-requests: read" in workflow
    assert "independent_readback:" in workflow
    assert "not_applicable:" in workflow
    assert "github.event.workflow_run.event != 'pull_request'" in workflow
    assert "github.event.workflow_run.event == 'pull_request'" in workflow
    assert "listPullRequestsAssociatedWithCommit" in workflow
    assert "pr.state === 'open'" in workflow
    assert "pr.base.ref === 'main'" in workflow
    assert "pr.head.sha === source.head_sha" in workflow
    assert workflow.index("Checkout trusted validator from main") < workflow.index("Collect sanitized GitHub evidence")
    assert "needs.producer.result == 'success'" in workflow
    assert "head_sha:source.head_sha" in workflow
    assert "EXPECTED_HEAD_SHA" in workflow
    assert "permissions: write" not in workflow
    assert "ref: ${{ github.event.workflow_run.head_sha }}" not in workflow
    assert "pull_request_target" not in workflow
