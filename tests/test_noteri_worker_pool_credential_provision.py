from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import noteri_worker_pool_credential_provision as provision
from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_stage as stage


class PrivateFileFixture:
    def open_exclusive(self, path: Path) -> int:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    def open_private_read(self, path: Path) -> int:
        return os.open(path, os.O_RDONLY)

    def validate_private_fd(self, fd: int) -> None:
        assert os.fstat(fd).st_nlink == 1

    def path_matches_fd(self, fd: int, path: Path, *, private: bool) -> bool:
        return private and os.path.samestat(os.fstat(fd), path.stat())


class CredentialProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        release = self.root / reference.RELEASES_RELATIVE / reference.SOURCE_SHA
        (release / "app").mkdir(parents=True)
        source = release / "app" / "secure_file.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        (release / "manifest.json").write_text(json.dumps({
            "schema_version": "1",
            "kind": "noteri_worker_pool_stage_only",
            "source_sha": reference.SOURCE_SHA,
            "source_repo": stage.EXPECTED_REPO,
            "activated": False,
            "files": {"app/secure_file.py": stage.file_sha256(source)},
        }), encoding="utf-8")

    def call(self, **overrides) -> dict:
        options = {
            "localappdata": self.root, "hostname": "Noteri",
            "profile": "NORMAL", "platform": "nt",
            "confirm": provision.CONFIRM,
            "secure_module": PrivateFileFixture(),
            "token_factory": lambda _: "fixture-token-" + "a" * 48,
        }
        options.update(overrides)
        return provision.provision(**options)

    def test_creates_private_fixed_file_with_readback_and_replay(self) -> None:
        first = self.call()
        self.assertEqual(first["result"], "CREDENTIAL_PROVISIONED")
        self.assertTrue(first["state_changed"])
        self.assertTrue(first["credential_readback"])
        token = self.root / reference.TOKEN_RELATIVE
        original = token.read_bytes()
        self.assertEqual(self.call()["result"], "ALREADY_PROVISIONED")
        self.assertEqual(token.read_bytes(), original)
        self.assertNotIn("fixture-token", str(first))

    def test_wrong_context_never_creates_file(self) -> None:
        self.assertEqual(self.call(confirm="wrong")["result"], "BLOCKED_CONTEXT")
        self.assertEqual(self.call(profile="ESTUDO")["result"], "BLOCKED_CONTEXT")
        self.assertFalse((self.root / reference.TOKEN_RELATIVE).exists())

    def test_preexisting_untrusted_file_is_not_overwritten(self) -> None:
        token = self.root / reference.TOKEN_RELATIVE
        token.parent.mkdir(parents=True)
        token.write_text("existing", encoding="utf-8")

        class RejectingFile(PrivateFileFixture):
            def open_private_read(self, path: Path) -> int:
                raise PermissionError("fixture")
        result = self.call(secure_module=RejectingFile())
        self.assertEqual(result["result"], "BLOCKED_PREFLIGHT")
        self.assertEqual(token.read_text(encoding="utf-8"), "existing")

    def test_generator_failure_never_creates_file(self) -> None:
        result = self.call(token_factory=lambda _: "short")
        self.assertEqual(result["result"], "BLOCKED_GENERATOR")
        self.assertFalse((self.root / reference.TOKEN_RELATIVE).parent.exists())

    def test_existing_invalid_private_file_blocks_replay(self) -> None:
        token = self.root / reference.TOKEN_RELATIVE
        token.parent.mkdir(parents=True)
        token.write_text("short", encoding="utf-8")
        result = self.call()
        self.assertEqual(result["result"], "BLOCKED_PREFLIGHT")
        self.assertEqual(token.read_text(encoding="utf-8"), "short")

    def test_concurrent_creation_never_overwrites_file(self) -> None:
        token = self.root / reference.TOKEN_RELATIVE

        class RacingFile(PrivateFileFixture):
            def open_exclusive(self, path: Path) -> int:
                path.write_text("concurrent", encoding="utf-8")
                raise FileExistsError("race")
        result = self.call(secure_module=RacingFile())
        self.assertEqual(result["result"], "BLOCKED_CONCURRENT")
        self.assertEqual(token.read_text(encoding="utf-8"), "concurrent")


if __name__ == "__main__":
    unittest.main()
