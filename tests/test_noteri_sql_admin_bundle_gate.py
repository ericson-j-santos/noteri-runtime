"""Fail-closed tests for protected SQL admin bundle attestation."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

SRC = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_admin_bundle_gate.py"
spec = importlib.util.spec_from_file_location("noteri_sql_admin_bundle_gate_test", SRC)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)

SHA = "a" * 40
SAFE_ACL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
CHILD_ACL = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
USER_WRITE_ACL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"


def manifest_payload() -> tuple[dict, dict[str, bytes]]:
    files = {name: (f"fixed sample: {name}").encode() for name in gate.FILES}
    payload = {
        "schema": gate.SCHEMA, "host": "Noteri", "environment": "dev",
        "capability": "sql-errorlog-readonly", "source_sha": SHA,
        "files": {name: hashlib.sha256(content).hexdigest()
                  for name, content in files.items()},
    }
    return payload, files


def test_protected_acl_accepts_only_system_and_admin():
    gate.validate_sddl(SAFE_ACL, protected=True)
    gate.validate_sddl(CHILD_ACL, protected=False)


@pytest.mark.parametrize("sddl,protected,code", [
    (USER_WRITE_ACL, True, "admin_acl_writable_principal_unverified"),
    (SAFE_ACL.replace("O:BA", "O:BU"), True, "admin_acl_owner_or_dacl_unverified"),
    (SAFE_ACL.replace("D:P", "D:"), True, "admin_acl_not_protected"),
    (SAFE_ACL.replace(";;;BA", ";;;WD"), True, "admin_acl_writable_principal_unverified"),
    (SAFE_ACL.replace(";;;BA", ";;;AU"), True, "admin_acl_writable_principal_unverified"),
    ("O:BAD:P(A;OICI;FA;;;SY)", True, "admin_acl_principal_missing"),
    ("O:BAD:P", True, "admin_acl_entries_unverified"),
    ("O:BAD:P(A;OICI;FA;;;SY)(D;OICI;FA;;;BA)", True, "admin_acl_writable_principal_unverified"),
    ("O:BAD:P(A;OICI;GR;;;SY)(A;OICI;FA;;;BA)", True, "admin_acl_rights_unverified"),
    ("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)", False,
     "admin_acl_writable_principal_unverified"),
])
def test_insecure_or_ambiguous_acl_fails_closed(sddl, protected, code):
    with pytest.raises(gate.Blocked, match=code):
        gate.validate_sddl(sddl, protected=protected)


def test_manifest_positive_and_replay_do_not_mutate():
    manifest, files = manifest_payload()
    before = json.dumps(manifest, sort_keys=True)
    gate.validate_manifest(manifest, files, SHA)
    gate.validate_manifest(manifest, files, SHA)
    assert json.dumps(manifest, sort_keys=True) == before


@pytest.mark.parametrize("changed,code", [
    ({"environment": "prod"}, "admin_manifest_binding_invalid"),
    ({"host": "Other"}, "admin_manifest_binding_invalid"),
    ({"source_sha": "b" * 40}, "admin_manifest_binding_invalid"),
    ({"capability": "shell"}, "admin_manifest_binding_invalid"),
    ({"unexpected": True}, "admin_manifest_schema_invalid"),
])
def test_manifest_rejects_untrusted_metadata(changed, code):
    manifest, files = manifest_payload()
    manifest.update(changed)
    with pytest.raises(gate.Blocked, match=code):
        gate.validate_manifest(manifest, files, SHA)


def test_manifest_rejects_byte_tampering_or_missing_dependency():
    manifest, files = manifest_payload()
    target = next(iter(files))
    files[target] += b"MALICIOUS"
    with pytest.raises(gate.Blocked, match="admin_bundle_integrity_mismatch"):
        gate.validate_manifest(manifest, files, SHA)
    files.pop(target)
    with pytest.raises(gate.Blocked, match="admin_manifest_file_set_invalid"):
        gate.validate_manifest(manifest, files, SHA)


def test_manifest_rejects_extra_file_and_bad_digest():
    manifest, files = manifest_payload()
    manifest["files"]["shell.py"] = "0" * 64
    with pytest.raises(gate.Blocked, match="admin_manifest_file_set_invalid"):
        gate.validate_manifest(manifest, files, SHA)
    manifest, files = manifest_payload()
    target = next(iter(files))
    manifest["files"][target] = "invalid"
    with pytest.raises(gate.Blocked, match="admin_manifest_digest_invalid"):
        gate.validate_manifest(manifest, files, SHA)


def test_manifest_rejects_wrong_head_and_empty_bytes():
    manifest, files = manifest_payload()
    with pytest.raises(gate.Blocked, match="source_sha_invalid"):
        gate.validate_manifest(manifest, files, "main")
    target = next(iter(files))
    files[target] = b""
    with pytest.raises(gate.Blocked, match="admin_bundle_file_invalid"):
        gate.validate_manifest(manifest, files, SHA)


def test_readonly_full_preflight_virtualized(monkeypatch):
    """Mock the physical filesystem only, exercising the full decision chain."""
    manifest, files = manifest_payload()
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    visited: list[str] = []

    def directory(path):
        visited.append("directory:" + str(path))

    def read(path, maximum):
        visited.append("read:" + path.name)
        if path.name == "manifest.json":
            return json.dumps(manifest).encode("utf-8")
        return files[path.name]

    monkeypatch.setattr(gate, "_directory", directory)
    monkeypatch.setattr(gate, "_regular", read)
    positive = gate.attest(SHA, platform="nt", host="Noteri", descriptor=lambda path: SAFE_ACL)
    again = gate.attest(SHA, platform="nt", host="Noteri", descriptor=lambda path: SAFE_ACL)
    assert again == positive
    assert positive["status"] == "ready"
    assert positive["elevated_execution_performed"] is False
    assert positive["sql_read_performed"] is False
    assert "read:manifest.json" in visited


def test_readonly_full_preflight_blocks_unsafe_manifest_acl(monkeypatch):
    manifest, files = manifest_payload()
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setattr(gate, "_directory", lambda path: None)
    def read(path, maximum):
        return json.dumps(manifest).encode("utf-8") if path.name == "manifest.json" else files[path.name]
    monkeypatch.setattr(gate, "_regular", read)
    with pytest.raises(gate.Blocked, match="admin_acl_writable_principal_unverified"):
        gate.attest(SHA, platform="nt", host="Noteri",
                    descriptor=lambda p: USER_WRITE_ACL if p.name == "manifest.json" else SAFE_ACL)


def test_reparse_file_refused(tmp_path):
    content = tmp_path / "sample"
    content.write_text("not secret")
    link = tmp_path / "manifest.json"
    link.symlink_to(content)
    with pytest.raises(gate.Blocked, match="admin_file_not_regular"):
        gate._regular(link, gate.MAX_MANIFEST_BYTES)


def test_cli_non_windows_fails_without_probing_paths(capsys):
    if os.name == "nt":
        pytest.skip("non-Windows negative control")
    assert gate.main(["--expected-sha", SHA]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "status": "blocked", "code": "noteri_windows_required", "schema": gate.SCHEMA,
    }


def test_attest_rejects_invalid_sha_before_filesystem_probes():
    with pytest.raises(gate.Blocked, match="source_sha_invalid"):
        gate.attest("main", platform="nt", host="Noteri")


@pytest.mark.skipif(os.name != "nt", reason="Windows Win32 API required")
def test_win32_descriptor_is_readable_without_mutation():
    path = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    sddl = gate._descriptor(path)
    assert isinstance(sddl, str) and sddl.startswith("O:") and "D:" in sddl


def test_readonly_contract_has_no_installation_or_elevation():
    text = SRC.read_text(encoding="utf-8")
    for banned in ("ShellExecuteW(", "schtasks.exe", "icacls.exe", "SetNamedSecurityInfoW",
                   "SetFileSecurityW", "TrustServerCertificate=Yes", "CREATE LOGIN",
                   "subprocess.run(", "os.system(", "runas"):
        assert banned not in text
    assert "elevated_execution_performed" in text
    assert "sql_read_performed" in text
