"""Teste de transação de manifesto isolado: não altera modelo verdadeiro."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "noteri_qwen7b_manifest_atomic_repair",
    ROOT / "scripts" / "noteri_qwen7b_manifest_atomic_repair.py",
)
assert spec and spec.loader
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class AtomicTests(unittest.TestCase):
    def test_original_status_never_mutates(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "7b"
            p.write_bytes(b"hello")
            result = m.inspect_state(p, Path(td) / "absent")
            self.assertFalse(result["official_manifest_installed"])
            self.assertFalse(result["state_changed"])

    def test_expected_pin_declared(self):
        self.assertEqual(len(m.EXPECTED_LOCAL_SHA), 64)
        self.assertEqual(len(m.EXPECTED_OFFICIAL_SHA256), 64)
        self.assertNotEqual(m.EXPECTED_LOCAL_SHA, m.EXPECTED_OFFICIAL_SHA256)
        self.assertEqual(m.ACTION, "noteri.qwen7b.manifest.reconcile.v1")

    def test_reject_wrong_official_bytes_without_writing_backup(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "7b"
            b = Path(td) / "backup"
            lock = Path(td) / "lock"
            p.write_bytes(b"local")
            with self.assertRaisesRegex(m.RepairBlocked, "OFFICIAL_BYTES_MISMATCH"):
                m.replace_transaction(p, b, lock, b"untrusted")
            self.assertFalse(b.exists())
            self.assertEqual(p.read_bytes(), b"local")

    def test_idempotent_atomic_swap_with_mocked_pins(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "7b"
            b = Path(td) / "backup"
            lock = Path(td) / "lock"
            before, after = b"local", b"trusted-public-manifest"
            p.write_bytes(before)
            with patch.object(m, "EXPECTED_LOCAL_SHA", m.sha(before)), \
                 patch.object(m, "EXPECTED_OFFICIAL_SHA256", m.sha(after)), \
                 patch.object(m, "ollama_process_state", return_value="ABSENT"), \
                 patch.object(m, "inspect_windows_listener", return_value="ABSENT"):
                result = m.replace_transaction(p, b, lock, after)
                self.assertEqual(result["result"], "MANIFEST_ATOMICALLY_RECONCILED")
                self.assertEqual(p.read_bytes(), after)
                self.assertEqual(b.read_bytes(), before)
                self.assertFalse(lock.exists())
                replay = m.replace_transaction(p, b, lock, after)
                self.assertEqual(replay["result"], "MANIFEST_ALREADY_RECONCILED")
                self.assertFalse(replay["state_changed"])

    def test_quiescence_guard_keeps_original(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "7b"
            b = Path(td) / "backup"
            lock = Path(td) / "lock"
            before, after = b"local", b"official"
            p.write_bytes(before)
            with patch.object(m, "EXPECTED_LOCAL_SHA", m.sha(before)), \
                 patch.object(m, "EXPECTED_OFFICIAL_SHA256", m.sha(after)), \
                 patch.object(m, "ollama_process_state", return_value="PRESENT"):
                response = m.replace_transaction(p, b, lock, after)
                self.assertEqual(response["result"], "BLOCKED_ROLLED_BACK")
                self.assertEqual(p.read_bytes(), before)

    def test_lock_refuses_replay(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "7b"
            b = Path(td) / "backup"
            lock = Path(td) / "lock"
            before, after = b"local", b"official"
            p.write_bytes(before)
            lock.write_bytes(b"other-owner")
            with patch.object(m, "EXPECTED_LOCAL_SHA", m.sha(before)), \
                 patch.object(m, "EXPECTED_OFFICIAL_SHA256", m.sha(after)):
                with self.assertRaisesRegex(m.RepairBlocked, "EXCLUSIVE_LOCK_BUSY"):
                    m.replace_transaction(p, b, lock, after)
                self.assertEqual(lock.read_bytes(), b"other-owner")

    def test_no_download_weight_or_service_start(self):
        code = (ROOT / "scripts" / "noteri_qwen7b_manifest_atomic_repair.py").read_text("utf-8")
        for forbidden in ("Popen(", "ollama pull", "curl ", "Start-Service", "Restart-Service", "os.system("):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
