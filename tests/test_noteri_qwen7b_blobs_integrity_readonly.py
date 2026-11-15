"""Integrity scanner: real SHA256 bytes, same-size corruption, no model start."""
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
spec=importlib.util.spec_from_file_location("noteri_qwen_blobs_sha256",
    ROOT/"scripts/noteri_qwen7b_blobs_integrity_readonly.py")
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)


def fixture(home: Path):
    store=home/".ollama"/"models"
    blobs=store/"blobs"
    blobs.mkdir(parents=True)
    entries=[]
    for data in (b"hello world", b"config bytes"):
        digest=hashlib.sha256(data).hexdigest()
        (blobs/("sha256-"+digest)).write_bytes(data)
        entries.append({"digest":"sha256:"+digest,"size":len(data)})
    manifest=store/"manifests/registry.ollama.ai/library/qwen2.5-coder/7b"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"config":entries[0],"layers":[entries[1]]}),
                        encoding="utf-8")
    return entries,blobs


class Tests(TestCase):
    def test_good_hashes_do_not_approve_different_model_pin(self):
        with TemporaryDirectory() as tmp:
            out=m.verify_store(Path(tmp),False)
            self.assertEqual(out["result"],"BLOCKED_STORE_INTEGRITY")
            fixture(Path(tmp))
            out=m.verify_store(Path(tmp),False)
            self.assertEqual(out["result"],"STORE_BLOBS_SHA256_VERIFIED")
            self.assertEqual(out["blobs_sha256_verified"],2)
            self.assertFalse(out["model_ready"])
            self.assertFalse(out["manifest_pin_match"])

    def test_tamper_same_size_rejected(self):
        with TemporaryDirectory() as tmp:
            entries,blobs=fixture(Path(tmp))
            name=entries[1]["digest"].split(":")[1]
            file=blobs/("sha256-"+name)
            file.write_bytes(b"bad bytes!!!")
            out=m.verify_store(Path(tmp),False)
            self.assertEqual(out["blobs_bad"],1)
            self.assertEqual(out["result"],"BLOCKED_STORE_INTEGRITY")

    def test_missing_blob_rejected(self):
        with TemporaryDirectory() as tmp:
            entries,blobs=fixture(Path(tmp))
            (blobs/("sha256-"+entries[1]["digest"].split(":")[1])).unlink()
            out=m.verify_store(Path(tmp),False)
            self.assertEqual(out["result"],"BLOCKED_STORE_INTEGRITY")

    def test_custom_store_unattested(self):
        with TemporaryDirectory() as tmp:
            self.assertEqual(m.verify_store(Path(tmp),True)["reason"],
                             "CUSTOM_STORE_UNVERIFIED")

    def test_unsafe_path_rejected(self):
        with TemporaryDirectory() as tmp:
            with patch.object(m,"path_safe",return_value=False):
                self.assertEqual(m.verify_store(Path(tmp),False)["reason"],"UNSAFE_PATH")

    def test_no_mutating_process_or_network(self):
        src=(ROOT/"scripts/noteri_qwen7b_blobs_integrity_readonly.py").read_text("utf-8")
        for token in ("subprocess.run(","Popen(","os.system(","ollama pull","http://","requests.get("):
            self.assertNotIn(token,src)
        self.assertIn("out[\"model_ready\"]",src.replace('"model_ready": False','out["model_ready"] = False') if "out[\"model_ready\"]" not in src else src)
