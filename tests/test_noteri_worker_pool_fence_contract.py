"""Exact cross-repository contract check, without invoking a Gateway or host.

The issuer is pinned to a real Rules Git object and must be revalidated when
its source SHA changes. Only its pure JSON functions are evaluated.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

from scripts import noteri_worker_pool_fence_sink as sink

RULES_COMMIT = "85bba14fac012127e5162aebb2d3875696bfb966"
RULES_FILE_SHA256 = "155cb58aede1a830f84de5e235638932aafaabb7cdeb92f7f74816b295fdd578"
ISSUER_SOURCE = Path(__file__).resolve().parents[1] / "_rules_fence" / "scripts" / "noteri_gateway_fencing.py"


def _verified_issuer():
    raw = ISSUER_SOURCE.read_bytes()  # Missing pinned checkout is a hard failure.
    assert hashlib.sha256(raw).hexdigest() == RULES_FILE_SHA256, "RULES_ISSUER_SOURCE_DRIFT"
    tree = ast.parse(raw, filename=str(ISSUER_SOURCE))
    constants = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"KIND", "TARGET", "DIR", "COUNTER", "ACTIVE"}):
            constants[node.targets[0].id] = ast.literal_eval(node.value)
    assert set(constants) == {"KIND", "TARGET", "DIR", "COUNTER", "ACTIVE"}
    pure = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"_serial", "_counter"}
    ]
    assert len(pure) == 2 and all(isinstance(n, ast.FunctionDef) for n in pure)
    env = {"hashlib": hashlib, "json": json, "Any": Any, **constants}
    # The exact, hash-verified issuer source is trusted; do not execute its
    # I/O or state mutation functions. Only these two pure function AST nodes.
    exec(compile(ast.Module(body=pure, type_ignores=[]),
                 str(ISSUER_SOURCE), "exec"), env)
    return constants, env["_counter"]


def test_pinned_rules_source_and_exact_counter_serialization():
    constants, issue_counter = _verified_issuer()
    assert constants == {
        "KIND": sink.KIND,
        "TARGET": sink.TARGET,
        "DIR": sink.GATEWAY_RELATIVE[-1],
        "COUNTER": "counter.json",
        "ACTIVE": "active.claim",
    }
    for sequence in (0, 1, 7, 2**32, sink.MAX_SEQUENCE):
        for host in ("noteri", "Noteri", "different-host"):
            assert issue_counter(sequence, host) == sink._expected_counter(sequence, host)


def test_issuer_claim_fields_match_sink_required_schema():
    raw = ISSUER_SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RULES_FILE_SHA256
    tree = ast.parse(raw)
    issuer_method = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "issue_local_token"
    )
    # The issuer's initial claim is an AST dict literal; assert that the
    # destination's expected fields cannot drift silently.
    claim_assign = next(
        node for node in ast.walk(issuer_method)
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "claim"
    )
    assert isinstance(claim_assign.value, ast.Dict)
    keys = {ast.literal_eval(key) for key in claim_assign.value.keys}
    assert keys == {
        "kind", "target", "host", "pid", "session_id",
        "correlation_id", "snapshot_sha256", "nonce",
    }
    # Sequence is added only after the counter has been persisted.
    issue_source = ast.get_source_segment(raw.decode("utf-8"), issuer_method)
    assert 'issued_claim = {**claim, "sequence": next_sequence}' in issue_source
    assert 'gateway.atomic_write_state_text(' in issue_source


def test_no_issuer_side_effects_or_runtime_authorization():
    raw = ISSUER_SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RULES_FILE_SHA256
    tree = ast.parse(raw)
    # The importer is explicitly limited to two pure functions, and neither
    # may invoke Gateway filesystem/dispatch or shell primitives.
    for name in ("_serial", "_counter"):
        node = next(x for x in tree.body
                    if isinstance(x, ast.FunctionDef) and x.name == name)
        used = ast.get_source_segment(raw.decode("utf-8"), node)
        for forbidden in ("gateway.", "os.", "subprocess.", "socket.", "open("):
            assert forbidden not in used, (name, forbidden)
