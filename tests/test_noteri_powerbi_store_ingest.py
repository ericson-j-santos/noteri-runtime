from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FAKE_ID = "Fake_Restricted_GDrive_Source_00001"
SOURCE = Path(__file__).resolve().parents[1] / "scripts/noteri_powerbi_store_ingest.py"
spec = importlib.util.spec_from_file_location("private_ingest", SOURCE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "chatgpt-workers" / "runtime-assets" / "powerbi-store"
        self.source_sha = "a" * 40
        self.session = "powerbi-store-test-1"
        self.file = b"PBIX-test-fixture-nonprod" * 40
        self.patches = [
            patch.object(mod, "EXPECTED_BYTES", len(self.file)),
            patch.object(mod, "EXPECTED_SHA256", hashlib.sha256(self.file).hexdigest()),
            patch.object(mod, "SOURCE_ID_SHA256", hashlib.sha256(FAKE_ID.encode()).hexdigest()),
        ]
        for patched in self.patches:
            patched.start()
            self.addCleanup(patched.stop)

    def ingest(self, creds=lambda: "local-token", downloader=None, source_id=None, **override):
        return mod.ingest(source_sha=override.get("source_sha", self.source_sha),
                          session_id=override.get("session_id", self.session),
                          root=override.get("root", self.root),
                          credential_provider=creds,
                          source_id_provider=source_id or (lambda: FAKE_ID),
                          downloader=downloader or (lambda _token, _id: self.file),
                          host=override.get("host", "Noteri"),
                          platform=override.get("platform", "nt"))

    def blocked(self, code, fn):
        with self.assertRaises(mod.Blocked) as exc:
            fn()
        self.assertEqual(code, exc.exception.code)

    def preflight(self, **kwargs):
        return mod.probe_prerequisites(
            source_sha=kwargs.get("source_sha", self.source_sha),
            session_id=kwargs.get("session_id", self.session),
            host=kwargs.get("host", "Noteri"),
            platform=kwargs.get("platform", "nt"),
            source_id_provider=kwargs.get("source_id_provider", lambda: FAKE_ID),
            credential_presence_provider=kwargs.get("cred", lambda: True),
        )

    def layout(self, *, host="Noteri", platform="nt", source_path=None):
        return mod.probe_source_layout(
            source_sha=self.source_sha, session_id=self.session,
            host=host, platform=platform,
            source_path=source_path or (Path(self.tmp.name) / "ProgramData" /
                "ReqSys" / "PowerBIStore" / "source-file-id.txt"),
        )

    def test_source_layout_no_write_or_credential_call(self):
        path = Path(self.tmp.name) / "ProgramData" / "ReqSys" / "PowerBIStore"
        path.parent.mkdir(parents=True)
        before = sorted(x.as_posix() for x in Path(self.tmp.name).rglob("*"))
        with patch.object(mod, "_credential_present_windows", side_effect=AssertionError("token checked")):
            r = self.layout()
        self.assertEqual(r["layout"], {
            "programdata": "EXPECTED_TYPE", "reqsys": "EXPECTED_TYPE",
            "store": "MISSING", "source_config": "MISSING"})
        self.assertFalse(r["acl_verified"])
        self.assertFalse(r["credential_metadata_checked"])
        self.assertFalse(r["transport_ready"])
        self.assertFalse(r["mutations_performed"])
        self.assertEqual(before, sorted(x.as_posix() for x in Path(self.tmp.name).rglob("*")))
        self.assertEqual(r, self.layout())

    def test_source_layout_wrong_host_denied(self):
        self.blocked("NOTERI_WINDOWS_REQUIRED",lambda:self.layout(host="other"))
        self.blocked("NOTERI_WINDOWS_REQUIRED",lambda:self.layout(platform="posix"))

    def test_source_layout_rejects_reparse(self):
        basedir=Path(self.tmp.name)/"ProgramData"
        basedir.mkdir()
        (basedir/"ReqSys").symlink_to(basedir, target_is_directory=True)
        result=self.layout()
        self.assertEqual(result["layout"]["reqsys"],"REPARSE_REJECTED")

    def test_source_layout_no_secret_data_in_receipt(self):
        r=json.dumps(self.layout())
        self.assertNotIn(FAKE_ID, r)
        self.assertNotIn(mod.CRED_TARGET, r)
        self.assertNotIn(str(mod.SOURCE_CONFIG), r)

    def test_preflight_read_only_success_not_transport_ready(self):
        before = list(Path(self.tmp.name).rglob("*"))
        r = self.preflight()
        self.assertEqual(r["status"], "PREREQUISITES_PRESENT_UNVERIFIED")
        self.assertTrue(r["source_config_digest_verified"])
        self.assertTrue(r["credential_metadata_present"])
        self.assertFalse(r["credential_freshness_validated"])
        self.assertFalse(r["credential_scope_validated"])
        self.assertFalse(r["gateway_session_validated_by_probe"])
        self.assertFalse(r["transport_ready"])
        self.assertFalse(r["mutations_performed"])
        self.assertEqual(list(Path(self.tmp.name).rglob("*")), before)

    def test_preflight_missing_credential_blocks(self):
        self.blocked("CREDENTIAL_UNAVAILABLE", lambda: self.preflight(cred=lambda: False))
        self.assertFalse(self.root.exists())

    def test_preflight_rejects_bad_config_without_reading_credential(self):
        called = []
        self.blocked("SOURCE_ID_UNAPPROVED", lambda: self.preflight(
            source_id_provider=lambda: "X" * 32,
            cred=lambda: called.append(True) or True))
        self.assertEqual(called, [])

    def test_preflight_wrong_host_blocks_before_secret_probe(self):
        called = []
        self.blocked("NOTERI_WINDOWS_REQUIRED", lambda: self.preflight(
            host="Other", cred=lambda: called.append(True) or True))
        self.assertEqual(called, [])

    def test_preflight_missing_config_blocks_before_credential(self):
        self.blocked("SOURCE_CONFIG_MISSING", lambda: self.preflight(
            source_id_provider=lambda: (_ for _ in ()).throw(mod.Blocked("SOURCE_CONFIG_MISSING")),
            cred=lambda: self.fail("credential probe must not run")))

    def test_preflight_repeat_idempotent(self):
        first = self.preflight()
        second = self.preflight()
        self.assertEqual(first, second)
        self.assertFalse(self.root.exists())

    def test_preflight_rejects_mixed_confirmation(self):
        from contextlib import redirect_stdout
        import io
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = mod.main(["--preflight-only", "--confirm", mod.CONFIRM,
                             "--source-sha", self.source_sha, "--session-id", self.session])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(buf.getvalue())["reason"], "AMBIGUOUS_PREFLIGHT")

    def test_credential_probe_nonwindows_no_token(self):
        with patch.object(mod.os, "name", "posix"):
            self.assertFalse(mod._credential_present_windows())

    def test_positive_and_real_independent_readback(self):
        receipt=self.ingest()
        self.assertEqual(receipt["status"],"INGESTED_AND_VERIFIED")
        self.assertTrue(receipt["disk_sha256_readback_verified"])
        self.assertFalse(receipt["independent_effect_verified"])
        self.assertFalse(receipt["transport_ready"])
        self.assertFalse(receipt["powerbi_opened"])
        self.assertEqual((self.root/mod.FILE_NAME).read_bytes(),self.file)

    def test_replay_does_not_need_token_or_network(self):
        self.ingest()
        receipt=self.ingest(creds=lambda: (_ for _ in ()).throw(ValueError("no token")),
                            downloader=lambda token, sid: (_ for _ in ()).throw(ValueError("no net")))
        self.assertEqual(receipt["status"], "ALREADY_PRESENT_AND_VERIFIED")
        self.assertEqual(len(list(self.root.glob("*.pbix"))),1)

    def test_missing_credential_blocks_before_directory_creation(self):
        self.blocked("CREDENTIAL_UNAVAILABLE", lambda: self.ingest(creds=lambda: ""))
        self.assertFalse(self.root.exists())

    def test_auth_provider_raises_blocked(self):
        self.blocked("CREDENTIAL_UNAVAILABLE",lambda:self.ingest(
            creds=lambda: (_ for _ in ()).throw(mod.Blocked("CREDENTIAL_UNAVAILABLE"))))

    def test_unapproved_source_id_blocks_before_credentials(self):
        self.blocked("SOURCE_ID_UNAPPROVED", lambda: self.ingest(source_id=lambda: "x" * 30))
        self.assertFalse(self.root.exists())

    def test_source_config_absent_blocks_without_creds(self):
        with patch.object(mod, "SOURCE_CONFIG", Path(self.tmp.name) / "missing.cfg"):
            self.blocked("SOURCE_CONFIG_MISSING", mod._load_source_id)

    def test_source_config_access_denied_differentiated(self):
        with patch.object(mod.Path, "open", side_effect=PermissionError("access denied")):
            self.blocked("SOURCE_CONFIG_ACCESS_DENIED", mod._load_source_id)

    def test_wrong_size_rejects_file(self):
        self.blocked("SOURCE_SIZE_MISMATCH",lambda:self.ingest(downloader=lambda token, sid:b"bad"))
        self.assertFalse(self.root.exists())

    def test_wrong_hash_rejects_file(self):
        forged=b"x"*len(self.file)
        self.blocked("SOURCE_HASH_MISMATCH",lambda:self.ingest(downloader=lambda token, sid:forged))
        self.assertFalse(self.root.exists())

    def test_existing_bad_file_preserved(self):
        self.root.mkdir(parents=True)
        target=self.root/mod.FILE_NAME
        target.write_bytes(b"BAD")
        self.blocked("TARGET_CONTENT_CONFLICT",lambda:self.ingest())
        self.assertEqual(target.read_bytes(),b"BAD")

    def test_reject_wrong_host(self):
        self.blocked("NOTERI_WINDOWS_REQUIRED",lambda:self.ingest(host="Desktop"))

    def test_reject_wrong_platform(self):
        self.blocked("NOTERI_WINDOWS_REQUIRED",lambda:self.ingest(platform="posix"))

    def test_reject_injected_arbitrary_root(self):
        self.blocked("ROOT_NOT_ALLOWLISTED",lambda:self.ingest(root=Path(self.tmp.name)/"Downloads"))

    def test_reject_symlink_in_parent(self):
        destination=Path(self.tmp.name)/"trusted"
        destination.mkdir()
        (Path(self.tmp.name)/"chatgpt-workers").symlink_to(destination, target_is_directory=True)
        self.blocked("REPARSE_PATH_REJECTED",lambda:self.ingest())

    def test_reject_symlink_at_target(self):
        self.root.mkdir(parents=True)
        real=self.root/"real.bin"
        real.write_bytes(self.file)
        (self.root/mod.FILE_NAME).symlink_to(real)
        self.blocked("REPARSE_PATH_REJECTED",lambda:self.ingest())

    def test_reject_bad_sha(self):
        self.blocked("INVALID_SOURCE_SHA",lambda:self.ingest(source_sha="bad"))

    def test_reject_bad_session(self):
        self.blocked("INVALID_SESSION_ID",lambda:self.ingest(session_id="bad id"))

    def test_cli_rejects_confirmation_mismatch(self):
        from contextlib import redirect_stdout
        import io
        buf=io.StringIO()
        with redirect_stdout(buf):
            code=mod.main(["--confirm","BAD","--source-sha",self.source_sha,"--session-id",self.session])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(buf.getvalue())["reason"],"CONFIRMATION_REJECTED")

    def test_unauthorized_url_or_path_not_a_cli_argument(self):
        parser_error="" # only confirmation, source SHA, session id are accepted
        self.assertNotIn("--url",SOURCE.read_text())
        self.assertNotIn("--output",SOURCE.read_text())

    def test_failed_downloader_does_not_write(self):
        self.blocked("DRIVE_AUTH_OR_TRANSPORT_FAILED",lambda:self.ingest(
            downloader=lambda token, sid: (_ for _ in ()).throw(mod.Blocked("DRIVE_AUTH_OR_TRANSPORT_FAILED"))))
        self.assertFalse(self.root.exists())

if __name__ == "__main__": unittest.main()
