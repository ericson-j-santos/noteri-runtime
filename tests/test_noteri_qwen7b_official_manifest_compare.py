"""Testes de comparação determinística, sem rede real nem mudança do modelo."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "noteri_qwen7b_official_manifest_compare",
    ROOT / "scripts" / "noteri_qwen7b_official_manifest_compare.py",
)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def fixture_bytes(tag: str = "same") -> tuple[bytes, str, int]:
    payload = (b"payload-for-test-" + tag.encode("utf-8"))
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    manifest = {"schemaVersion": 2,
                "config": {"digest": digest, "size": len(payload)},
                "layers": [{"digest": "sha256:" + hashlib.sha256(b"extra").hexdigest(),
                            "size": len(b"extra")}]}
    return json.dumps(manifest, separators=(",", ":")).encode(), digest, len(payload)


class CompareTests(unittest.TestCase):
    def test_equal_reference_with_encoding_difference(self):
        with TemporaryDirectory() as tmp:
            raw, _, _ = fixture_bytes()
            pretty = json.dumps(json.loads(raw), indent=2).encode()
            result = m.compare(raw, pretty, Path(tmp))
            self.assertEqual(result["classification"], "SAME_JSON_DIFFERENT_ENCODING")
            self.assertEqual(result["official_blobs_size_missing"], 2)
            self.assertFalse(result["repair_authorized"])
            self.assertFalse(result["model_ready"])

    def test_full_blob_reuse_with_metadata_difference_not_approved(self):
        with TemporaryDirectory() as tmp:
            raw, first, size = fixture_bytes()
            local = json.loads(raw)
            official = dict(local)
            official["annotations"] = {"version": "official"}
            store = Path(tmp)
            blobs = store / "blobs"
            blobs.mkdir()
            (blobs / first.replace(":", "-")).write_bytes(b"payload-for-test-same")
            second = local["layers"][0]["digest"]
            (blobs / second.replace(":", "-")).write_bytes(b"extra")
            result = m.compare(raw, json.dumps(official).encode(), store)
            self.assertEqual(result["official_blobs_size_missing"], 0)
            self.assertEqual(result["classification"], "SAME_BLOBS_DIFFERENT_METADATA")
            self.assertFalse(result["manifest_replaced"])
            self.assertFalse(result["model_ready"])
            self.assertEqual(result["verified_official_blobs_by_hash"], 0)

    def test_missing_official_references_fail_closed(self):
        with TemporaryDirectory() as tmp:
            raw, _, _ = fixture_bytes()
            different, _, _ = fixture_bytes("official")
            result = m.compare(raw, different, Path(tmp))
            self.assertEqual(result["classification"], "OFFICIAL_BLOBS_MISSING_DO_NOT_REPLACE")
            self.assertGreater(result["official_blob_bytes_missing"], 0)

    def test_invalid_and_duplicate_descriptors_denied(self):
        for data in (
            b"invalid",
            b'{"layers":[]}',
            b'{"config":{"digest":"sha256:x","size":1},"layers":[{}]}',
        ):
            with self.subTest(data=data), self.assertRaises(m.CompareBlocked):
                m.parse_descriptors(data)

    def test_registry_redirect_not_followed(self):
        with self.assertRaises(m.CompareBlocked):
            m.NoRedirect().redirect_request(None, None, 302, "", None, "https://example.com")

    def test_registry_pinned_endpoint_and_readonly(self):
        source = (ROOT / "scripts" / "noteri_qwen7b_official_manifest_compare.py").read_text("utf-8")
        self.assertIn('https://registry.ollama.ai/v2/library/qwen2.5-coder/manifests/7b', source)
        self.assertIn('EXPECTED_PREFIX = "dae161e27b0e"', source)
        for forbidden in ("Popen(", "subprocess.run(", "write_bytes(", "ollama pull", "os.system(", "shell=True"):
            self.assertNotIn(forbidden, source)

    def test_local_and_official_equal_not_model_ready(self):
        with TemporaryDirectory() as tmp:
            raw, _, _ = fixture_bytes()
            result = m.compare(raw, raw, Path(tmp))
            self.assertEqual(result["classification"], "ALREADY_OFFICIAL")
            self.assertFalse(result["model_ready"])


if __name__ == "__main__":
    unittest.main()
