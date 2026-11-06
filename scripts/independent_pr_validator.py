#!/usr/bin/env python3
"""Validador independente, fail-closed e vinculado ao SHA da PR."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_JOBS = (
    "tests",
    "SQL admin guard / Win32 contract (not Noteri)",
    "Synthetic forensic receipt / Windows producer",
    "Synthetic forensic receipt / cross-runner readback",
)


class ValidationError(ValueError):
    """Evidência incompleta, divergente ou não confiável."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate(evidence: dict[str, Any], expected_repository: str) -> dict[str, Any]:
    """Valida evidência sanitizada e retorna recibo determinístico."""
    _require(evidence.get("schema_version") == 1, "schema_version inválido")
    _require(evidence.get("source") == "github_workflow_run_and_api", "fonte inválida")
    _require(evidence.get("repository") == expected_repository, "repositório divergente")

    run = evidence.get("workflow_run") or {}
    pr = evidence.get("pull_request") or {}
    main_sha = evidence.get("main_sha")
    head_sha = run.get("head_sha")
    _require(run.get("name") == "CI", "workflow de origem não é CI")
    _require(run.get("event") == "pull_request", "evento de origem não é pull_request")
    _require(run.get("status") == "completed", "workflow de origem não terminou")
    _require(run.get("conclusion") == "success", "workflow de origem não passou")
    _require(isinstance(run.get("id"), int) and run["id"] > 0, "run_id inválido")
    _require(isinstance(head_sha, str) and SHA40.fullmatch(head_sha) is not None, "head SHA inválido")
    _require(isinstance(main_sha, str) and SHA40.fullmatch(main_sha) is not None, "main SHA inválido")

    _require(isinstance(pr.get("number"), int) and pr["number"] > 0, "PR inválida")
    _require(pr.get("state") == "open", "PR não está aberta")
    _require(pr.get("base_ref") == "main", "base não é main")
    _require(pr.get("head_sha") == head_sha, "PR avançou após o CI")
    _require(pr.get("base_sha") == main_sha, "PR está desatualizada em relação à main")
    _require(pr.get("author") not in (None, "", "github-actions[bot]"), "autor da PR inválido")
    _require(pr.get("author") != evidence.get("validator_identity"), "autoavaliação não permitida")

    jobs = evidence.get("jobs")
    _require(isinstance(jobs, list), "jobs ausentes")
    by_name = {job.get("name"): job for job in jobs if isinstance(job, dict)}
    for name in REQUIRED_JOBS:
        _require(name in by_name, f"job obrigatório ausente: {name}")
        job = by_name[name]
        _require(job.get("head_sha") == head_sha, f"job em SHA divergente: {name}")
        _require(job.get("status") == "completed", f"job não terminou: {name}")
        _require(job.get("conclusion") == "success", f"job não passou: {name}")
        steps = job.get("steps")
        _require(isinstance(steps, list) and steps, f"steps ausentes: {name}")
        for step in steps:
            step_name = str(step.get("name") or "<sem nome>")
            _require(step.get("status") == "completed", f"step não terminou: {name} / {step_name}")
            _require(step.get("conclusion") == "success", f"step não passou: {name} / {step_name}")

    _require(evidence.get("unresolved_review_threads") == 0, "há thread de revisão não resolvida")
    changed_files = evidence.get("changed_files")
    _require(isinstance(changed_files, list) and 0 < len(changed_files) <= 300, "diff vazio ou excessivo")
    _require(len(set(changed_files)) == len(changed_files), "arquivos alterados duplicados")
    _require(all(isinstance(path, str) and path and not path.startswith("/") for path in changed_files), "caminho alterado inválido")
    _require(isinstance(evidence.get("diff_digest"), str) and SHA256.fullmatch(evidence["diff_digest"]) is not None, "digest do diff inválido")

    return {
        "schema_version": 1,
        "verdict": "INDEPENDENT_VALIDATOR_PASSED",
        "repository": expected_repository,
        "pull_request": pr["number"],
        "head_sha": head_sha,
        "base_sha": main_sha,
        "source_run_id": run["id"],
        "required_jobs": list(REQUIRED_JOBS),
        "changed_files": sorted(changed_files),
        "diff_digest": evidence["diff_digest"],
        "unresolved_review_threads": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    receipt = validate(evidence, args.expected_repository)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
