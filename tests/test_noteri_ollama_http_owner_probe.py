"""Provas negativas e positivas da sonda Ollama HTTP/porta sem mudanças."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "noteri_ollama_http_owner_probe",
    ROOT / "scripts" / "noteri_ollama_http_owner_probe.py",
)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class Reply:
    status = 200
    headers = {"Content-Type": "application/json"}
    def __init__(self, value): self.raw = json.dumps(value).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, limit): return self.raw[:limit]


class Tests(unittest.TestCase):
    def test_disallow_other_routes(self):
        with self.assertRaisesRegex(m.ProbeBlocked, "ROUTE_NOT_ALLOWLISTED"):
            m.local_http_json("/api/generate")

    def test_valid_version_response(self):
        with patch.object(m.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = Reply({"version": "0.12.2"})
            data = m.local_http_json("/api/version")
        self.assertEqual(data["result"], "VERSION_OK")

    def test_target_requires_full_official_digest(self):
        with patch.object(m.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = Reply({
                "models": [{"name": "qwen2.5-coder:7b", "digest": "a" * 64}]
            })
            data = m.local_http_json("/api/tags")
        self.assertEqual(data["result"], "TARGET_DIGEST_MISMATCH")
        self.assertFalse(data["official_digest_match"])

    def test_official_digest_passes_only_one_matching_tag(self):
        with patch.object(m.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = Reply({
                "models": [{"name": "qwen2.5-coder:7b", "digest": m.EXPECTED_DIGEST}]
            })
            data = m.local_http_json("/api/tags")
        self.assertEqual(data["result"], "MODEL_DIGEST_OK")

    def test_no_models_never_approves(self):
        with patch.object(m.urllib.request, "build_opener") as factory:
            factory.return_value.open.return_value = Reply({"models": []})
            data = m.local_http_json("/api/tags")
        self.assertEqual(data["result"], "TARGET_MODEL_NOT_UNIQUELY_FOUND")

    def test_redirect_denied(self):
        with self.assertRaisesRegex(m.ProbeBlocked, "REDIRECT_DENIED"):
            m.RejectRedirect().redirect_request(None, None, 302, "", None, "https://bad.example")

    def test_no_external_or_mutating_calls(self):
        content = (ROOT / "scripts" / "noteri_ollama_http_owner_probe.py").read_text("utf-8")
        self.assertIn("http://127.0.0.1:11434", content)
        for forbidden in ("method=\"POST\"", "Popen(", "ollama pull", "shell=True",
                          "os.system(", "kill(", "terminate(", "write_bytes("):
            self.assertNotIn(forbidden, content)


if __name__ == "__main__":
    unittest.main()
