from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_credential_reference as probe

SHA = probe.SOURCE_SHA


class SecureFixture:
    def __init__(self, *, matches: bool = True):
        self.matches = matches
        self.opened = False

    def open_private_read(self, path: Path) -> int:
        self.opened = True
        return os.open(path, os.O_RDONLY)

    def validate_private_fd(self, fd: int) -> None:
        assert fd >= 0

    def path_matches_fd(self, fd: int, path: Path, *, private: bool) -> bool:
        assert private is True
        return self.matches


class CredentialReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def release(self) -> Path:
        release = self.root / probe.RELEASES_RELATIVE / SHA
        (release / "app").mkdir(parents=True)
        source = release / "app" / "secure_file.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (release / "manifest.json").write_text(json.dumps({
            "schema_version": "1",
            "kind": "noteri_worker_pool_stage_only",
            "source_sha": SHA,
            "source_repo": stage.EXPECTED_REPO,
            "activated": False,
            "files": {"app/secure_file.py": stage.file_sha256(source)},
        }), encoding="utf-8")
        return release

    def call(self, **overrides) -> dict:
        options = {
            "localappdata": self.root, "hostname": "Noteri",
            "profile": "NORMAL", "platform": "nt",
            "secure_module": SecureFixture(),
        }
        options.update(overrides)
        return probe.qualify(**options)

    def test_missing_reference_blocks_without_reading_token(self) -> None:
        self.release()
        result = self.call()
        self.assertEqual(result["result"], "BLOCKED_TOKEN_REFERENCE")
        self.assertFalse(result["token_bytes_read"])
        self.assertFalse(result["state_changed"])

    def test_private_reference_without_token_bytes(self) -> None:
        self.release()
        token = self.root / probe.TOKEN_RELATIVE
        token.parent.mkdir(parents=True)
        token.write_text("fixture-not-an-operational-secret", encoding="utf-8")
        secure = SecureFixture()
        result = self.call(secure_module=secure)
        self.assertTrue(secure.opened)
        self.assertEqual(result["result"], "REFERENCE_PRIVATE_UNREAD")
        self.assertTrue(result["private_reference"])
        self.assertFalse(result["activated"])
        self.assertNotIn("fixture-not-an-operational-secret", json.dumps(result))
        self.assertNotIn(str(token), json.dumps(result))

    def test_wrong_host_or_profile_blocks_before_file_access(self) -> None:
        secure = SecureFixture()
        self.assertEqual(self.call(hostname="Other", secure_module=secure)["result"], "BLOCKED_HOST")
        self.assertEqual(self.call(profile="ESTUDO", secure_module=secure)["result"], "BLOCKED_HOST")
        self.assertFalse(secure.opened)

    def test_tampered_release_blocks_before_credential_access(self) -> None:
        release = self.release()
        (release / "app" / "secure_file.py").write_text("tampered\n", encoding="utf-8")
        secure = SecureFixture()
        self.assertEqual(self.call(secure_module=secure)["result"], "BLOCKED_RELEASE")
        self.assertFalse(secure.opened)

    def test_directory_and_link_reference_are_rejected(self) -> None:
        self.release()
        token = self.root / probe.TOKEN_RELATIVE
        token.mkdir(parents=True)
        self.assertEqual(self.call()["result"], "BLOCKED_TOKEN_FILE")
        token.rmdir()
        target = self.root / "other"
        target.write_text("fixture", encoding="utf-8")
        token.symlink_to(target)
        self.assertEqual(self.call()["result"], "BLOCKED_REFERENCE_INTEGRITY")

    def test_changed_file_identity_is_rejected(self) -> None:
        self.release()
        token = self.root / probe.TOKEN_RELATIVE
        token.parent.mkdir(parents=True)
        token.write_text("fixture", encoding="utf-8")
        self.assertEqual(
            self.call(secure_module=SecureFixture(matches=False))["result"],
            "BLOCKED_TOKEN_FILE",
        )


if __name__ == "__main__":
    unittest.main()
