"""Risk2 Ollama: rejection and bounded rollback, no real service start."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
spec=importlib.util.spec_from_file_location("noteri_ollama_start_governed",
    ROOT/"scripts/noteri_ollama_start_governed.py")
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)

SHA="f"*40
ARGS=dict(action=m.ACTION,environment="DEV",
          correlation_id="noteri-ollama-start-tests-20261115",
          idempotency_key=m.IDEMPOTENCY_KEY,confirmation=m.CONFIRM,
          expected_sha=SHA,host="Noteri",platform="nt",profile="NORMAL")

class Tests(TestCase):
    def test_exact_valid_request_only(self):
        self.assertIsNone(m.validate_request(**ARGS))
        for key,bad in (("action","run"),("environment","PROD"),("host","other"),
                        ("platform","posix"),("profile","ESTUDO"),("expected_sha","bad"),
                        ("confirmation","guess"),("idempotency_key","different")):
            args={**ARGS,key:bad}
            with self.subTest(key=key),self.assertRaises(m.StartBlocked):
                m.validate_request(**args)

    def test_model_attestation_requires_digest(self):
        for value in ({"status":"UNAVAILABLE","present":False,"digest":None},
                      {"status":"PRESENT","present":True,"digest":"a"*64},
                      {"status":"ABSENT","present":False,"digest":None}):
            with patch.object(m,"read_model_tags",return_value=value):
                self.assertIsNone(m.model_readback())
        with patch.object(m,"read_model_tags",return_value={
            "status":"PRESENT","present":True,
            "digest":"dae161e27b0e"+"0"*52
        }):
            self.assertEqual(len(m.model_readback()),64)

    def test_preflight_denies_unknown_listener(self):
        report={"status":"BLOCKED_OR_INCONCLUSIVE","windows_tcp_listener":"UNKNOWN"}
        with patch.object(m,"preflight_plan",return_value=report):
            with self.assertRaisesRegex(m.StartBlocked,"OLLAMA_EXISTING_OR_INCONCLUSIVE"):
                m.eligible_preflight(expected_sha=SHA,correlation_id=ARGS["correlation_id"],root=ROOT)

    def test_preflight_denies_wrong_binary_digest(self):
        report={"status":"PREFLIGHT_CANDIDATE","windows_tcp_listener":"ABSENT",
                "process":"ABSENT","port":"UNKNOWN",
                "binaries":[{"candidate":"USER_PROGRAM","status":"PRESENT","sha256":"a"*64},
                            {"status":"MISSING"},{"status":"MISSING"}]}
        with patch.object(m,"preflight_plan",return_value=report):
            with self.assertRaisesRegex(m.StartBlocked,"BINARY_UNTRUSTED"):
                m.eligible_preflight(expected_sha=SHA,correlation_id=ARGS["correlation_id"],root=ROOT)

    def test_start_never_invokes_process_when_hash_wrong(self):
        with patch.object(m,"fixed_binary",side_effect=m.StartBlocked("BINARY_SHA_MISMATCH")), \
             patch.object(m,"spawn_exact_binary") as spawn:
            with self.assertRaisesRegex(m.StartBlocked,"BINARY_SHA_MISMATCH"):
                m.start_once(expected_sha=SHA,correlation_id=ARGS["correlation_id"],
                             root=ROOT,local=ROOT)
            spawn.assert_not_called()

    def test_race_guard_blocks_process_launch(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            state=Path(tmp)
            with patch.object(m,"fixed_binary",return_value=ROOT), \
                 patch.object(m,"eligible_preflight",return_value={}), \
                 patch.object(m,"receipt_root",return_value=state), \
                 patch.object(m,"inspect_windows_listener",return_value="UNKNOWN"), \
                 patch.object(m,"spawn_exact_binary") as spawn:
                result=m.start_once(expected_sha=SHA,correlation_id=ARGS["correlation_id"],
                                    root=ROOT,local=ROOT)
            self.assertEqual(result["result"],"BLOCKED_OLLAMA_START_AND_ROLLBACK")
            spawn.assert_not_called()

    def test_rollback_kills_only_own_process(self):
        class Fake:
            def __init__(self): self.pid=33;self.terminated=False
            def poll(self): return 1 if self.terminated else None
            def terminate(self): self.terminated=True
            def wait(self,timeout): return 1
        with patch.object(m,"inspect_windows_listener",return_value="ABSENT"):
            self.assertTrue(m.rollback_owned(Fake()))

    def test_script_has_no_download_or_admin(self):
        src=(ROOT/"scripts/noteri_ollama_start_governed.py").read_text("utf-8")
        for banned in ("shell=True","ollama pull","curl ","Start-Service",
                       "Restart-Service","schtasks","runas","sudo "):
            self.assertNotIn(banned,src)
        self.assertIn('"OLLAMA_NO_CLOUD"] = "1"',src)
        self.assertIn('"OLLAMA_HOST"] = "127.0.0.1:11434"',src)
        self.assertIn('creationflags=(subprocess.DETACHED_PROCESS',src)
