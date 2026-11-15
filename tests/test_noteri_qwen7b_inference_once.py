"""Testes negativos/positivos da execução mínima de inferência local."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
spec=importlib.util.spec_from_file_location(
    "noteri_qwen7b_inference_once", ROOT/"scripts"/"noteri_qwen7b_inference_once.py")
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)


def valid_tags():
    return {"result":"MODEL_DIGEST_OK","target_digest":m.EXPECTED_DIGEST}


class Tests(unittest.TestCase):
    def test_refuses_active_models_before_generate(self):
        with patch.object(m, "listener_pids", return_value=[123]), \
             patch.object(m, "identify_pids", return_value=[{"pid":123,"name":"ollama.exe"}]), \
             patch.object(m, "local_http_json", side_effect=[
                 {"result":"VERSION_OK","version":"0.40.14"}, valid_tags()]), \
             patch.object(m, "request_json", return_value={"models":[{"model":"other"}]}) as req:
            with self.assertRaisesRegex(m.ProbeBlocked,"ANOTHER_MODEL_ALREADY_LOADED"):
                m.infer_once()
            req.assert_called_once_with("/ps",None,timeout=8)

    def test_denies_wrong_port_owner(self):
        with patch.object(m,"listener_pids",return_value=[22]), \
             patch.object(m,"identify_pids",return_value=[{"pid":22,"name":"other.exe"}]), \
             patch.object(m,"request_json") as api:
            with self.assertRaisesRegex(m.ProbeBlocked,"OLLAMA_PORT_OWNER_NOT_UNIQUE"):
                m.infer_once()
            api.assert_not_called()

    def test_denies_different_digest(self):
        with patch.object(m,"listener_pids",return_value=[123]), \
             patch.object(m,"identify_pids",return_value=[{"pid":123,"name":"ollama.exe"}]), \
             patch.object(m,"local_http_json",side_effect=[
                 {"result":"VERSION_OK","version":"0.40.14"},
                 {"result":"TARGET_DIGEST_MISMATCH","target_digest":"a"*64}]), \
             patch.object(m,"request_json") as api:
            with self.assertRaisesRegex(m.ProbeBlocked,"QWEN7B_NOT_INDEPENDENTLY_ATTESTED"):
                m.infer_once()
            api.assert_not_called()

    def test_succeeds_only_on_real_model_done_and_tokens(self):
        with patch.object(m,"listener_pids",return_value=[123]), \
             patch.object(m,"identify_pids",return_value=[{"pid":123,"name":"ollama.exe"}]), \
             patch.object(m,"local_http_json",side_effect=[
                 {"result":"VERSION_OK","version":"0.40.14"},valid_tags()]), \
             patch.object(m,"request_json",side_effect=[
                 {"models":[]},
                 {"model":m.MODEL,"done":True,"response":"READY","eval_count":2}]):
            out=m.infer_once()
            self.assertEqual(out["result"],"QWEN7B_LOCAL_INFERENCE_PROVED")
            self.assertTrue(out["responded_exactly_ready"])
            self.assertEqual(out["tokens_generated"],2)
            self.assertFalse(out["state_changed_persistently"])

    def test_rejects_empty_or_ungenerated_response(self):
        for answer in ({"model":m.MODEL,"done":True,"response":"","eval_count":1},
                       {"model":m.MODEL,"done":False,"response":"READY","eval_count":1},
                       {"model":"unknown","done":True,"response":"READY","eval_count":1},
                       {"model":m.MODEL,"done":True,"response":"READY","eval_count":0}):
            with self.subTest(answer=answer), \
                 patch.object(m,"listener_pids",return_value=[123]), \
                 patch.object(m,"identify_pids",return_value=[{"pid":123,"name":"ollama.exe"}]), \
                 patch.object(m,"local_http_json",side_effect=[
                     {"result":"VERSION_OK","version":"0.40.14"},valid_tags()]), \
                 patch.object(m,"request_json",side_effect=[{"models":[]},answer]):
                with self.assertRaisesRegex(m.ProbeBlocked,"INFERENCE_RESPONSE_NOT_PROVED"):
                    m.infer_once()

    def test_fixed_post_with_no_cloud_or_download(self):
        code=(ROOT/"scripts"/"noteri_qwen7b_inference_once.py").read_text("utf-8")
        self.assertIn('http://127.0.0.1:11434/api',code)
        self.assertIn('"keep_alive": 0',code)
        self.assertIn('"num_predict": 12',code)
        for forbidden in ("ollama pull","Popen(","shell=True","os.system(",
                          "https://", "127.0.0.1:11435", "subprocess.run("):
            self.assertNotIn(forbidden,code)

    def test_allowlisted_request_paths(self):
        with self.assertRaises(m.ProbeBlocked):
            m.request_json("/pull", {}, timeout=1)
        with self.assertRaises(m.ProbeBlocked):
            m.request_json("/generate", None, timeout=1)


if __name__ == "__main__":
    unittest.main()
