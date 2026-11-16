"""Regression for read-only Noteri Win32 access probe (never DELETE/RENAME)."""
from __future__ import annotations

import ctypes
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_winerror5_access_readonly as p


class FakeProc:
    def __init__(self, value):
        self.value = value
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.value


class FakeKernel:
    def __init__(self, handle):
        self.CreateFileW = FakeProc(handle)
        self.CloseHandle = FakeProc(1)


class AccessProbeTests(unittest.TestCase):
    def test_request_delete_opens_existing_only_and_never_modifies(self):
        k = FakeKernel(812)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "target.txt"
            path.write_bytes(b"retained")
            r = p.probe_existing(path, p.DELETE, kernel=k)
            self.assertTrue(r["granted"])
            self.assertEqual(path.read_bytes(), b"retained")
            self.assertEqual(k.CreateFileW.calls[0][1], p.DELETE)
            self.assertEqual(k.CreateFileW.calls[0][2], p.FILE_SHARE_ALL)
            self.assertEqual(k.CreateFileW.calls[0][4], p.OPEN_EXISTING)
            self.assertEqual(k.CreateFileW.calls[0][5],
                             p.FILE_FLAG_OPEN_REPARSE_POINT)
            self.assertEqual(len(k.CloseHandle.calls), 1)

    def test_directory_probe_uses_open_existing_backup_semantics(self):
        k = FakeKernel(15)
        with tempfile.TemporaryDirectory() as temp:
            r = p.probe_existing(Path(temp), p.FILE_DELETE_CHILD,
                                 directory=True, kernel=k)
            self.assertTrue(r["granted"])
            self.assertEqual(k.CreateFileW.calls[0][5],
                             p.FILE_FLAG_OPEN_REPARSE_POINT |
                             p.FILE_FLAG_BACKUP_SEMANTICS)

    def test_sharing_violation_classifies_but_does_not_close(self):
        k = FakeKernel(p.INVALID_HANDLE)
        with mock.patch.object(p.ctypes, "get_last_error", return_value=32):
            v = p.probe_existing(Path(r"C:\synthetic.txt"), p.DELETE, kernel=k)
        self.assertFalse(v["granted"])
        self.assertEqual(v["interpretation"], "SHARING_VIOLATION")
        self.assertEqual(len(k.CloseHandle.calls), 0)

    def test_access_denied_does_not_assume_acl_as_cause(self):
        k = FakeKernel(p.INVALID_HANDLE)
        with mock.patch.object(p.ctypes, "get_last_error", return_value=5):
            v = p.probe_existing(Path(r"C:\synthetic.txt"), p.DELETE, kernel=k)
        self.assertFalse(v["granted"])
        self.assertEqual(v["interpretation"], "ACCESS_DENIED")
        self.assertEqual(v["winerror"], 5)

    def test_other_error_is_not_misclassified(self):
        k = FakeKernel(p.INVALID_HANDLE)
        with mock.patch.object(p.ctypes, "get_last_error", return_value=87):
            v = p.probe_existing(Path(r"C:\synthetic.txt"), p.DELETE, kernel=k)
        self.assertFalse(v["granted"])
        self.assertEqual(v["interpretation"], "OTHER_WIN32_ERROR")

    def test_file_identity_is_stable_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file.txt"
            path.write_bytes(b"hello")
            first = p.file_identity(path)
            second = p.file_identity(path)
            self.assertEqual(first, second)
            self.assertEqual(path.read_bytes(), b"hello")

    def test_directory_as_target_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(p.Blocked, "DESTINATION_NOT_REGULAR"):
                p.file_identity(Path(tmp))

    def test_missing_target_is_not_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "missing"
            with self.assertRaises(FileNotFoundError):
                p.file_identity(target)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
