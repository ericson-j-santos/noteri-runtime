from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import noteri_worker_pool_activation_preflight as preflight
from scripts import noteri_worker_pool_credential_reference as reference


def _release(tmp_path: Path) -> Path:
    release = tmp_path / reference.RELEASES_RELATIVE / reference.SOURCE_SHA
    (release / "app").mkdir(parents=True)
    (release / "contracts" / "v1").mkdir(parents=True)
    files = {
        "app/__init__.py": b"",
        "app/main.py": b"app = None\n",
        "app/secure_file.py": b"pass\n",
        "contracts/v1/contract.json": b"{}\n",
        "requirements.txt": b"fastapi==0.137.2\n",
    }
    import hashlib
    for rel, data in files.items():
        path = release / rel
        path.write_bytes(data)
    (release / "manifest.json").write_text(json.dumps({
        "schema_version": "1", "kind": "noteri_worker_pool_stage_only",
        "source_sha": reference.SOURCE_SHA,
        "source_repo": preflight.stage.EXPECTED_REPO,
        "activated": False,
        "files": {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()},
    }), encoding="utf-8")
    return release


def _assess(tmp_path: Path, **kwargs) -> dict:
    options = dict(localappdata=tmp_path, hostname="Noteri", platform="nt", profile="NORMAL",
                   python_version=(3, 12), packages={"ready": True, "required_count": 1,
                                                    "missing": [], "version_mismatch": []},
                   listener="not_listening", task="absent_verified",
                   free_bytes=preflight.MIN_FREE_BYTES)
    options.update(kwargs)
    with patch.object(reference, "qualify", return_value={"result": "REFERENCE_PRIVATE_UNREAD"}):
        return preflight.assess(**options)


class ActivationPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_pins_and_optional_extras(self):
        path = self.root / "requirements.txt"
        path.write_text("fastapi==0.137.2\nuvicorn[standard]==0.34.2\n", encoding="utf-8")
        self.assertEqual(preflight.required_packages(path),
                         {"fastapi": "0.137.2", "uvicorn": "0.34.2"})
        path.write_text("fastapi>=0.137.2\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not_exactly_pinned"):
            preflight.required_packages(path)

    def test_preflight_does_not_activate_or_read_token(self):
        _release(self.root)
        result = _assess(self.root)
        self.assertEqual(result["result"], "READY_FOR_ACTIVATION_DESIGN")
        self.assertFalse(result["activated"])
        self.assertFalse(result["token_bytes_read"])
        self.assertFalse(result["state_changed"])
        self.assertFalse(result["activation_authorized"])

    def test_invalid_release_and_host_fail_closed(self):
        release = _release(self.root)
        self.assertEqual(_assess(self.root, profile="ESTUDO")["result"],
                         "BLOCKED_HOST_PROFILE")
        (release / "app" / "main.py").write_text("altered\n", encoding="utf-8")
        self.assertEqual(_assess(self.root)["result"], "BLOCKED_RELEASE")

    def test_missing_dependencies_and_unknown_task_block(self):
        _release(self.root)
        result = _assess(self.root, packages={"ready": False, "required_count": 1,
                                              "missing": ["fastapi"], "version_mismatch": []})
        self.assertEqual(result["result"], "BLOCKED_DEPENDENCIES")
        self.assertEqual(result["packages"]["missing"], ["fastapi"])
        self.assertEqual(_assess(self.root, task="absent_or_unreadable")["result"],
                         "BLOCKED_TASK_INVENTORY")

    def test_port_python_and_credential_fail_closed(self):
        _release(self.root)
        self.assertEqual(_assess(self.root, listener="listening_unverified")["result"],
                         "BLOCKED_PORT_OR_UNKNOWN_LISTENER")
        self.assertEqual(_assess(self.root, python_version=(3, 10))["result"],
                         "BLOCKED_PYTHON_VERSION")
        with patch.object(reference, "qualify", return_value={"result": "BLOCKED_TOKEN_FILE"}):
            self.assertEqual(preflight.assess(
                localappdata=self.root, hostname="Noteri", platform="nt", profile="NORMAL",
                python_version=(3, 12), packages={"ready": True},
                listener="not_listening", task="absent_verified",
                free_bytes=preflight.MIN_FREE_BYTES)["result"],
                "BLOCKED_CREDENTIAL_REFERENCE")


if __name__ == "__main__":
    unittest.main()
