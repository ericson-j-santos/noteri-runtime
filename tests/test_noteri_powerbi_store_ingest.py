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
            self.blocked("SOURCE_CONFIG_UNAVAILABLE", mod._load_source_id)

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
