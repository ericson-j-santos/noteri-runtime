from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

P = Path(__file__).resolve().parents[1] / "scripts" / "noteri_gateway_refresh.py"
S = importlib.util.spec_from_file_location("noteri_gateway_refresh", P)
m = importlib.util.module_from_spec(S)
sys.modules[S.name] = m
S.loader.exec_module(m)


def execution(attempt: int = 1):
    return {
        "repository": m.EXPECTED_WORKFLOW_REPOSITORY,
        "workflow_sha": "a" * 40,
        "run_id": 123,
        "run_attempt": attempt,
    }


def canonical_fixture():
    payloads = {
        destination: ("canonical:" + source).encode()
        for source, destination in m.RUNTIME_MAP.items()
    }
    entries = []
    for source, destination in m.RUNTIME_MAP.items():
        payload = payloads[destination]
        entries.append(
            {
                "path": source,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest = json.dumps(
        {"version": m.RULES_VERSION, "files": entries}, sort_keys=True
    ).encode()
    return manifest, payloads, m.canonical_files(manifest)


def write_snapshot(install: Path, expected: dict, previous: dict[str, bytes]):
    backup = install / "backup-test"
    entries = {}
    for destination, canonical in expected.items():
        existed = destination in previous
        entry = {
            "source": canonical["source"],
            "existed": existed,
            "desired_sha256": canonical["sha256"],
            "desired_size": canonical["size"],
        }
        if existed:
            target = backup.joinpath("files", *destination.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(previous[destination])
            observed = target.stat()
            entry.update(
                {
                    "previous_sha256": hashlib.sha256(previous[destination]).hexdigest(),
                    "previous_size": observed.st_size,
                    "previous_mode": stat.S_IMODE(observed.st_mode),
                    "previous_windows_state": {"version": 1},
                }
            )
        entries[destination] = entry
    backup.mkdir(parents=True, exist_ok=True)
    (backup / "rollback-manifest.json").write_text(
        json.dumps(
            {
                "version": 2,
                "metadata_contract": "windows-owner-group-dacl-ads-v1",
                "install_root": str(install.resolve()),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "entries": entries,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return backup


def seed_current_receipt(monkeypatch, root: Path):
    install = root / "install"
    monkeypatch.setattr(m, "INSTALL_ROOT", install)
    manifest, payloads, expected = canonical_fixture()
    for destination, payload in payloads.items():
        target = install.joinpath(*destination.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    previous = {name: ("previous:" + name).encode() for name in payloads}
    backup = write_snapshot(install, expected, previous)
    receipt = {
        "result": "HOST_UPDATE_OK",
        "source_commit": m.RULES_COMMIT,
        "rules_version": m.RULES_VERSION,
        "noteri_wsl_inventory_profile": True,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "host": m.EXPECTED_HOST,
        "install_root": str(install),
        "backup_dir": str(backup),
        "validation_head": m.RULES_COMMIT,
        "files": {
            name: {"sha256": meta["sha256"], "size": meta["size"]}
            for name, meta in expected.items()
        },
    }
    m.atomic_json(install / "update-receipt.json", receipt)
    return receipt, manifest, payloads, expected


def test_contract_is_fixed():
    assert m.RULES_COMMIT == "b5ade370fa11877ff7b899b5c6feacc3bfaf34e7"
    assert m.RULES_VERSION == "1.6.19"
    assert m.MANIFEST_SHA256 == "fbf4af678a11111b8a895bee1f19211523f0bdcb292838f64e252ab67d37f96c"
    assert m.INSTALL_ROOT == Path(r"C:\dev\chatgpt-command-gateway")
    assert m.INSTALL_SHA256 == "4b2c200680de7e0db6bd44905a246d7e1773b36d0f516d9756046e758827e35a"
    assert m.UPDATE_SHA256 == "fa5d03b0cecb46cf02477af4a75c81c57b92d7b609d4bd4abd54f28a7b22b1a2"
    assert m.LEGACY_VERIFY_SHA256 == "b792692d6c86bccccfba9037596d3a7cbd4996e7d560f257194efa020357bef4"


def test_rejects_other_host_confirmation_and_commit():
    with pytest.raises(m.RefreshError, match="host invalido"):
        m.validate("OTHER", m.CONFIRM, m.RULES_COMMIT)
    with pytest.raises(m.RefreshError, match="confirmacao invalida"):
        m.validate("Noteri", "WRONG", m.RULES_COMMIT)
    with pytest.raises(m.RefreshError, match="commit divergente"):
        m.validate("Noteri", m.CONFIRM, "0" * 40)


@pytest.mark.parametrize(
    ("repository", "workflow_sha", "run_id", "run_attempt"),
    [
        ("other/repo", "a" * 40, 1, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "bad", 1, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "a" * 40, 0, 1),
        (m.EXPECTED_WORKFLOW_REPOSITORY, "a" * 40, 1, 0),
    ],
)
def test_rejects_invalid_execution_identity(repository, workflow_sha, run_id, run_attempt):
    with pytest.raises(m.RefreshError):
        m.validate_execution(repository, workflow_sha, run_id, run_attempt)


def test_missing_legacy_pins_fails_before_updater_or_write(monkeypatch):
    manifest, _, _ = canonical_fixture()
    calls = {"fetch": 0, "write": 0}
    monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
    monkeypatch.setattr(m, "fetch", lambda *_args: manifest)
    monkeypatch.setattr(m, "atomic_json", lambda *_args: calls.__setitem__("write", calls["write"] + 1))
    with pytest.raises(m.RefreshError, match="pins legados obrigatorios"):
        m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution())
    assert calls == {"fetch": 0, "write": 0}


def test_old_install_is_revalidated_without_reassigning_installation(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt, manifest, _, _ = seed_current_receipt(monkeypatch, Path(tmp))
        update_path = m.INSTALL_ROOT / "update-receipt.json"
        original = update_path.read_bytes()
        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: True)
        monkeypatch.setattr(
            m,
            "fetch",
            lambda path, *_args: manifest
            if path == "MANIFEST.json"
            else pytest.fail("old install must not run updater"),
        )
        result = m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution())
        assert result["result"] == "NOTERI_GATEWAY_ALREADY_CURRENT_VERIFIED"
        assert update_path.read_bytes() == original
        assert "workflow_run_id" not in receipt
        run_receipt = json.loads(
            (m.INSTALL_ROOT / m.RUN_RECEIPT_NAME).read_text(encoding="utf-8")
        )
        assert run_receipt["installation_performed_by_run"] is False
        assert run_receipt["workflow_run_id"] == 123


def test_replay_cannot_be_relabelled_as_installation(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        _, manifest, _, _ = seed_current_receipt(monkeypatch, Path(tmp))
        update_path = m.INSTALL_ROOT / "update-receipt.json"
        original_hash = hashlib.sha256(update_path.read_bytes()).hexdigest()
        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: True)
        monkeypatch.setattr(m, "fetch", lambda *_args: manifest)
        first = m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution(1))
        second = m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution(2))
        assert first["result"] == second["result"] == "NOTERI_GATEWAY_ALREADY_CURRENT_VERIFIED"
        assert hashlib.sha256(update_path.read_bytes()).hexdigest() == original_hash
        run_receipt = json.loads(
            (m.INSTALL_ROOT / m.RUN_RECEIPT_NAME).read_text(encoding="utf-8")
        )
        assert run_receipt["workflow_run_attempt"] == 2
        assert run_receipt["installation_performed_by_run"] is False


def test_empty_rollback_manifest_fails_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt, _, _, expected = seed_current_receipt(monkeypatch, Path(tmp))
        Path(receipt["backup_dir"], "rollback-manifest.json").write_text("{}", encoding="utf-8")
        with pytest.raises(m.RefreshError, match="schema do rollback"):
            m.verify_update_receipt(receipt, expected)


def test_missing_and_corrupt_backup_fail_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt, _, _, expected = seed_current_receipt(monkeypatch, Path(tmp))
        backup = Path(receipt["backup_dir"])
        first = next(iter(sorted(m.MANAGED_FILES)))
        saved = backup.joinpath("files", *first.split("/"))
        saved.unlink()
        with pytest.raises(m.RefreshError, match="componente ausente"):
            m.verify_update_receipt(receipt, expected)
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(b"corrupt")
        with pytest.raises(m.RefreshError, match="arquivo de backup divergente"):
            m.verify_update_receipt(receipt, expected)


def test_snapshot_outside_install_root_fails_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
        receipt, _, _, expected = seed_current_receipt(monkeypatch, Path(tmp))
        receipt["backup_dir"] = outside
        with pytest.raises(m.RefreshError, match="backup fora da instalacao"):
            m.verify_update_receipt(receipt, expected)


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is not guaranteed on Windows")
def test_snapshot_intermediate_symlink_escape_fails_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        receipt, _, _, expected = seed_current_receipt(monkeypatch, root)
        backup = Path(receipt["backup_dir"])
        internal = backup / "files" / "bin"
        external = root / "external-backup-bin"
        internal.rename(external)
        internal.symlink_to(external, target_is_directory=True)
        with pytest.raises(m.RefreshError, match="componente reparse inseguro"):
            m.verify_update_receipt(receipt, expected)


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is not guaranteed on Windows")
def test_installed_intermediate_symlink_escape_fails_closed(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        receipt, _, _, expected = seed_current_receipt(monkeypatch, root)
        internal = m.INSTALL_ROOT / "bin"
        external = root / "external-installed-bin"
        internal.rename(external)
        internal.symlink_to(external, target_is_directory=True)
        with pytest.raises(m.RefreshError, match="componente reparse inseguro"):
            m.verify_update_receipt(receipt, expected)


def test_windows_reparse_attribute_on_intermediate_component_is_rejected(
    monkeypatch,
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "bin" / "managed.py"
        target.parent.mkdir()
        target.write_bytes(b"payload")
        real_lstat = m.os.lstat
        reparse_flag = getattr(m.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

        def mark_bin_as_reparse(path, *args, **kwargs):
            observed = real_lstat(path, *args, **kwargs)
            if not args and not kwargs and Path(path) == root / "bin":
                return SimpleNamespace(
                    st_mode=observed.st_mode,
                    st_file_attributes=(
                        getattr(observed, "st_file_attributes", 0) | reparse_flag
                    ),
                )
            return observed

        monkeypatch.setattr(m.os, "lstat", mark_bin_as_reparse)
        with pytest.raises(m.RefreshError, match="componente reparse inseguro"):
            m.confined_regular_file(
                root, "bin/managed.py", label="windows junction simulation"
            )


def test_coherent_local_file_and_receipt_tamper_fails_against_canonical(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt, _, _, expected = seed_current_receipt(monkeypatch, Path(tmp))
        relative = "bin/command_gateway.py"
        target = m.INSTALL_ROOT.joinpath(*relative.split("/"))
        target.write_bytes(b"coherent-local-tamper")
        receipt["files"][relative] = {
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "size": target.stat().st_size,
        }
        with pytest.raises(m.RefreshError, match="fonte canonica"):
            m.verify_update_receipt(receipt, expected)


def test_complete_update_proves_new_install_and_full_rollback(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        install = Path(tmp) / "install"
        monkeypatch.setattr(m, "INSTALL_ROOT", install)
        manifest, payloads, expected = canonical_fixture()
        previous = {}
        for destination in m.MANAGED_FILES:
            old = ("old:" + destination).encode()
            previous[destination] = old
            target = install.joinpath(*destination.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(old)

        def fake_fetch(path, *_args):
            return manifest if path == "MANIFEST.json" else b"verified-script"

        def fake_updater(args, **kwargs):
            assert (Path(args[1]).parent / "noteri_gateway_legacy_v1_rebaseline.py").read_bytes() == b"verified-script"
            assert "--noteri-wsl-inventory-profile" in args
            assert "--noteri-legacy-v1-rebaseline" in args
            assert args[args.index("--expected-legacy-receipt-sha256") + 1] == "a" * 64
            assert args[args.index("--expected-legacy-manifest-sha256") + 1] == "b" * 64
            assert kwargs["timeout"] == 180 and kwargs["check"] is False
            backup = write_snapshot(install, expected, previous)
            for destination, payload in payloads.items():
                target = install.joinpath(*destination.split("/"))
                target.write_bytes(payload)
            receipt = {
                "result": "HOST_UPDATE_OK",
                "source_commit": m.RULES_COMMIT,
                "rules_version": m.RULES_VERSION,
                "noteri_wsl_inventory_profile": True,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "host": m.EXPECTED_HOST,
                "install_root": str(install),
                "backup_dir": str(backup),
                "validation_head": m.RULES_COMMIT,
                "files": {
                    name: {"sha256": meta["sha256"], "size": meta["size"]}
                    for name, meta in expected.items()
                },
            }
            m.atomic_json(install / "update-receipt.json", receipt)
            return SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: pytest.fail("no UAC or admin escalation"))
        monkeypatch.setattr(m, "fetch", fake_fetch)
        monkeypatch.setattr(m.subprocess, "run", fake_updater)
        result = m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution(),
                                legacy_receipt_sha256="a" * 64,
                                legacy_manifest_sha256="b" * 64)
        assert result["result"] == "NOTERI_GATEWAY_REFRESHED"
        run_receipt = json.loads(
            (install / m.RUN_RECEIPT_NAME).read_text(encoding="utf-8")
        )
        assert run_receipt["installation_performed_by_run"] is True
        assert run_receipt["workflow_run_id"] == 123
        assert set(run_receipt["files"]) == m.MANAGED_FILES


def test_stale_successful_subprocess_receipt_is_rejected(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        receipt, manifest, _, _ = seed_current_receipt(monkeypatch, Path(tmp))
        receipt["source_commit"] = "0" * 40
        m.atomic_json(m.INSTALL_ROOT / "update-receipt.json", receipt)
        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(m, "is_admin", lambda: True)
        monkeypatch.setattr(m, "fetch", lambda path, *_args: manifest if path == "MANIFEST.json" else b"script")
        monkeypatch.setattr(m.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stderr=""))
        with pytest.raises(m.RefreshError, match="nao foi renovado"):
            m.run_elevated(m.CONFIRM, m.RULES_COMMIT, **execution(),
                           legacy_receipt_sha256="a" * 64,
                           legacy_manifest_sha256="b" * 64)


def test_atomic_json_cleans_owned_temp_but_preserves_divergent(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipt.json"
        monkeypatch.setattr(m.os, "replace", lambda *_args: (_ for _ in ()).throw(PermissionError("replace-failure")))
        with pytest.raises(PermissionError, match="replace-failure"):
            m.atomic_json(path, {"ok": True})
        assert list(Path(tmp).glob("receipt.json.tmp-*")) == []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "receipt.json"
        def diverge(source, _destination):
            Path(source).write_bytes(b"divergent")
            raise PermissionError("replace-failure")
        monkeypatch.setattr(m.os, "replace", diverge)
        with pytest.raises(PermissionError, match="replace-failure"):
            m.atomic_json(path, {"ok": True})
        leftovers = list(Path(tmp).glob("receipt.json.tmp-*"))
        assert len(leftovers) == 1 and leftovers[0].read_bytes() == b"divergent"


def blocked_updater_payload():
    return {
        "result": "HOST_UPDATE_LEGACY_PREFLIGHT_BLOCKED",
        "gateway_exit_code": 28,
        "transaction_id": "b" * 32,
        "source_commit": m.RULES_COMMIT,
        "phase": "install_runtime",
        "error": r"raw C:\\sensitive\\path must not leak",
        "failure": {
            "type": "RuntimeInstallError",
            "category": "install_runtime_os_error",
            "operation": "activate_stage",
            "destination": r"C:\\sensitive\\path",
            "raw_error": "must-not-leak",
            "os_error": {
                "errno": 13,
                "winerror": 5,
                "strerror": r"C:\\sensitive\\path",
            },
        },
        "mutation_started": True,
        "rollback_attempted": True,
        "rollback_succeeded": True,
        "rollback_error": None,
    }


def blocked_updater_stderr(payload=None):
    blocked = payload or blocked_updater_payload()
    warning = {
        "result": "HOST_UPDATE_LOCK_RELEASE_WARNING",
        "error": "raw warning must not leak",
    }
    return "non-json noise\n" + json.dumps(blocked) + "\n" + json.dumps(warning)


def test_updater_failure_is_sanitized_and_never_creates_success_receipt(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        install = Path(tmp) / "install"
        monkeypatch.setattr(m, "INSTALL_ROOT", install)
        manifest, _, _ = canonical_fixture()
        calls = 0

        def updater(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return SimpleNamespace(returncode=28, stderr=blocked_updater_stderr())

        monkeypatch.setattr(m.socket, "gethostname", lambda: "Noteri")
        monkeypatch.setattr(
            m, "fetch",
            lambda path, *_args: manifest if path == "MANIFEST.json" else b"payload",
        )
        monkeypatch.setattr(m.subprocess, "run", updater)
        with pytest.raises(m.UpdaterBlocked, match="updater_failed:28") as caught:
            m.run_elevated(
                m.CONFIRM, m.RULES_COMMIT, **execution(),
                legacy_receipt_sha256="a" * 64,
                legacy_manifest_sha256="b" * 64,
            )
        evidence = caught.value.evidence
        assert calls == 1
        assert evidence["evidence_authenticated"] is True
        assert evidence["phase"] == "install_runtime"
        assert evidence["failure_type"] == "RuntimeInstallError"
        assert evidence["failure_category"] == "install_runtime_os_error"
        assert evidence["failure_operation"] == "activate_stage"
        assert evidence["failure_os_error"] == {"errno": 13, "winerror": 5}
        serialized = json.dumps(evidence)
        for forbidden in (
            "sensitive", "must-not-leak", "strerror", "destination",
            "raw_error", "backup_dir", "receipt_path", "rollback_error",
            "primary_receipt_error",
        ):
            assert forbidden not in serialized
        assert not (install / m.RUN_RECEIPT_NAME).exists()


def test_reverse_scan_selects_last_authenticated_receipt_before_warning():
    first = blocked_updater_payload()
    first["transaction_id"] = "a" * 32
    first["phase"] = "replaceability_preflight"
    second = blocked_updater_payload()
    stderr = "\n".join([
        json.dumps(first), json.dumps(second),
        json.dumps({"result": "HOST_UPDATE_LOCK_RELEASE_WARNING"}),
    ])
    evidence = m.sanitize_updater_failure(stderr, 28)
    assert evidence["evidence_authenticated"] is True
    assert evidence["transaction_id"] == "b" * 32
    assert evidence["phase"] == "install_runtime"


def test_failure_evidence_artifact_is_exclusive_bound_hashed_and_sanitized(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        runner_temp = Path(tmp) / "runner-temp"
        runner_temp.mkdir()
        monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
        evidence = m.sanitize_updater_failure(blocked_updater_stderr(), 28)
        artifact = m.bind_failure_evidence(evidence, **execution())
        path, digest = m.persist_failure_evidence(artifact)
        observed = json.loads(path.read_text(encoding="utf-8"))
        assert observed == artifact
        assert artifact["managed_runtime_changed_by_capture"] is False
        assert path.name == m.FAILURE_ARTIFACT_NAME
        assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
        serialized = path.read_text(encoding="utf-8")
        for forbidden in (
            "sensitive", "must-not-leak", "strerror", "destination",
            "raw_error", "backup_dir", "receipt_path", "rollback_error",
            "primary_receipt_error",
        ):
            assert forbidden not in serialized
        with pytest.raises(m.RefreshError, match="already_exists"):
            m.persist_failure_evidence(artifact)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(source_commit="0" * 40),
        lambda p: p.update(result="HOST_UPDATE_OK"),
        lambda p: p.update(gateway_exit_code=3),
        lambda p: p.update(transaction_id="bad"),
        lambda p: p.update(phase="INVALID PHASE"),
        lambda p: p["failure"].update(type="bad type"),
        lambda p: p["failure"].update(os_error={"errno": True, "winerror": 5}),
        lambda p: p["failure"].update(os_error={"errno": 2 ** 40, "winerror": 5}),
    ],
)
def test_invalid_updater_failure_evidence_becomes_safe_unclassified(mutate):
    payload = blocked_updater_payload()
    mutate(payload)
    evidence = m.sanitize_updater_failure(blocked_updater_stderr(payload), 28)
    assert evidence["evidence_authenticated"] is False
    assert evidence["phase"] is None
    assert evidence["failure_type"] is None
    assert evidence["failure_os_error"] == {"errno": None, "winerror": None}


def test_duplicate_nonfinite_oversized_and_success_json_are_unclassified():
    duplicate = '{"result":"HOST_UPDATE_BLOCKED","result":"HOST_UPDATE_BLOCKED"}'
    nonfinite = '{"result":"HOST_UPDATE_BLOCKED","gateway_exit_code":NaN}'
    too_long = "x" * (m.MAX_UPDATER_LINE_BYTES + 1)
    too_large = "x\n" * (m.MAX_UPDATER_STDERR_BYTES // 2 + 1)
    success = json.dumps({"result": "HOST_UPDATE_OK", "source_commit": m.RULES_COMMIT})
    for stderr in (duplicate, nonfinite, too_long, too_large, success):
        evidence = m.sanitize_updater_failure(stderr, 28)
        assert evidence["evidence_authenticated"] is False
        assert evidence["updater_result"] is None


def test_missing_blocked_json_and_other_exit_code_are_unclassified():
    warning = json.dumps({"result": "HOST_UPDATE_LOCK_RELEASE_WARNING"})
    assert m.sanitize_updater_failure(warning, 28)["evidence_authenticated"] is False
    evidence = m.sanitize_updater_failure(blocked_updater_stderr(), 7)
    assert evidence["evidence_authenticated"] is False
    assert evidence["updater_exit_code"] == 7


def test_failure_artifact_readback_tamper_is_rejected(monkeypatch, tmp_path):
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    evidence = m.sanitize_updater_failure(blocked_updater_stderr(), 28)
    artifact = m.bind_failure_evidence(evidence, **execution())
    original = Path.read_bytes

    def tampered_readback(path):
        if path.name == m.FAILURE_ARTIFACT_NAME:
            return b"{}\n"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", tampered_readback)
    with pytest.raises(m.RefreshError, match="readback_invalid"):
        m.persist_failure_evidence(artifact)


def _main_argv():
    return [
        str(P), "--confirm", m.CONFIRM, "--commit", m.RULES_COMMIT,
        "--workflow-repository", m.EXPECTED_WORKFLOW_REPOSITORY,
        "--workflow-sha", "a" * 40, "--workflow-run-id", "123",
        "--workflow-run-attempt", "1",
    ]


def test_main_persists_failure_artifact_without_turning_failure_into_success(
    monkeypatch, capsys, tmp_path,
):
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    evidence = m.sanitize_updater_failure(blocked_updater_stderr(), 28)

    def blocked(*_args, **_kwargs):
        raise m.UpdaterBlocked(28, evidence)

    monkeypatch.setattr(m, "run_elevated", blocked)
    monkeypatch.setattr(sys, "argv", _main_argv())
    assert m.main() == 3
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert "error" not in envelope
    assert envelope["failure_evidence_persisted"] is True
    artifact_path = runner_temp / m.FAILURE_ARTIFACT_NAME
    artifact = json.loads(artifact_path.read_text())
    assert envelope["failure_evidence"] == artifact
    assert envelope["failure_evidence_sha256"] == hashlib.sha256(
        artifact_path.read_bytes()
    ).hexdigest()


def test_failure_artifact_persistence_error_does_not_mask_or_promote(
    monkeypatch, capsys, tmp_path,
):
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    (runner_temp / m.FAILURE_ARTIFACT_NAME).write_text("stale", encoding="utf-8")
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    evidence = m.sanitize_updater_failure(blocked_updater_stderr(), 28)
    monkeypatch.setattr(
        m, "run_elevated",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(m.UpdaterBlocked(28, evidence)),
    )
    monkeypatch.setattr(sys, "argv", _main_argv())
    assert m.main() == 3
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert "error" not in envelope
    assert envelope["failure_evidence_persisted"] is False
    assert envelope["failure_evidence_sha256"] is None
    assert envelope["failure_evidence"]["evidence_authenticated"] is True

