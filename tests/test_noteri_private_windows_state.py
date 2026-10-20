"""Offline tests for Noteri's minimal Windows protected-state primitives."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_private_windows_state as m


class _Procedure:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class NoteriPrivateWindowsStateTest(unittest.TestCase):
    def test_no_reparse_accepts_single_file_and_rejects_symlink_or_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular.bin"
            regular.write_bytes(b"x")
            m.no_reparse(regular)

            alias = root / "alias.bin"
            try:
                alias.symlink_to(regular)
            except OSError:
                alias = None
            if alias is not None:
                with self.assertRaisesRegex(m.ProtectedStateError, "reparse_path_blocked"):
                    m.no_reparse(alias)

            hardlink = root / "hardlink.bin"
            try:
                os.link(regular, hardlink)
            except OSError:
                hardlink = None
            if hardlink is not None:
                with self.assertRaisesRegex(m.ProtectedStateError, "hardlink_path_blocked"):
                    m.no_reparse(regular)

    @unittest.skipIf(os.name == "nt", "POSIX-only fail-closed control")
    def test_windows_only_primitives_fail_closed_off_windows(self) -> None:
        with self.assertRaisesRegex(m.ProtectedStateError, "dpapi_windows_required"):
            m.dpapi(b"value", encrypt=True)
        with self.assertRaisesRegex(m.ProtectedStateError, "windows_acl_required"):
            m.WindowsPrivateFiles()

    def test_dpapi_uses_ui_forbidden_without_machine_scope(self) -> None:
        output = ctypes.create_string_buffer(b"cipher")
        observed: dict[str, object] = {}

        def protect(_input, _description, _entropy, _reserved, _prompt, flags, result):
            observed["flags"] = flags
            result._obj.cbData = 6
            result._obj.pbData = ctypes.cast(output, ctypes.POINTER(ctypes.c_ubyte))
            return 1

        crypt = types.SimpleNamespace(
            CryptProtectData=_Procedure(protect),
            CryptUnprotectData=_Procedure(lambda *_args: 0),
        )
        kernel = types.SimpleNamespace(LocalFree=_Procedure(lambda _pointer: None))

        def fake_library(name: str, **_kwargs: object):
            return crypt if name == "crypt32" else kernel

        with patch.object(m.os, "name", "nt"), patch.object(
            m.ctypes, "WinDLL", side_effect=fake_library, create=True,
        ):
            self.assertEqual(m.dpapi(b"plain", encrypt=True), b"cipher")
        self.assertEqual(observed["flags"], 0x1)


if __name__ == "__main__":
    unittest.main()
