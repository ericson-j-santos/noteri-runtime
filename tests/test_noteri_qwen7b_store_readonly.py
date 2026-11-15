"""Testes de armazenamento Qwen7B, sem modelo real ou download."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
spec=importlib.util.spec_from_file_location("noteri_qwen7b_store_readonly",
    ROOT/"scripts/noteri_qwen7b_store_readonly.py")
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)

class Tests(TestCase):
    def test_missing_default_not_ready(self):
        with TemporaryDirectory() as tmp:
            r=m.assess_model_store(Path(tmp),False)
        self.assertEqual(r["manifest"],"MISSING_DEFAULT_STORE")
        self.assertFalse(r["model_ready"])

    def test_custom_store_not_called_missing(self):
        with TemporaryDirectory() as tmp:
            r=m.assess_model_store(Path(tmp),True)
        self.assertEqual(r["manifest"],"CUSTOM_STORE_UNVERIFIED")

    def test_invalid_manifest(self):
        with TemporaryDirectory() as tmp:
            home=Path(tmp)
            p=home/".ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/7b"
            p.parent.mkdir(parents=True)
            p.write_text("{",encoding="utf-8")
            r=m.assess_model_store(home,False)
        self.assertEqual(r["manifest"],"UNAVAILABLE_OR_INVALID")

    def test_blobs_missing_are_not_ready(self):
        with TemporaryDirectory() as tmp:
            home=Path(tmp)
            p=home/".ollama/models/manifests/registry.ollama.ai/library/qwen2.5-coder/7b"
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps({
                "config":{"digest":"sha256:"+"a"*64,"size":100},
                "layers":[{"digest":"sha256:"+"b"*64,"size":100}]
            }),encoding="utf-8")
            r=m.assess_model_store(home,False)
        self.assertEqual(r["manifest"],"PRESENT")
        self.assertEqual(r["blobs_checked"],2)
        self.assertEqual(r["blobs_missing_or_untrusted"],2)
        self.assertFalse(r["model_ready"])
        self.assertRegex(r["manifest_sha256"],r"^[0-9a-f]{64}$")
        self.assertTrue(r["manifest_sha256"])

    def test_symlink_path_fails_closed(self):
        with TemporaryDirectory() as tmp:
            with patch.object(m,"path_safe",return_value=False):
                self.assertEqual(m.assess_model_store(Path(tmp),False)["manifest"],
                                 "UNSAFE_PATH")

    def test_never_launch_or_download(self):
        code=(ROOT/"scripts/noteri_qwen7b_store_readonly.py").read_text("utf-8")
        for token in ("Popen(", "subprocess.run(", "ollama pull", "os.system(",
                      "Start-Service", "open(\"http"):
            self.assertNotIn(token,code)
        self.assertIn('"model_ready"',code)
