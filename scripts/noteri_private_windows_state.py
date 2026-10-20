"""Minimal Windows-only protection primitives for the Noteri runtime.

This module intentionally contains only host-local mechanisms: user-scope
DPAPI, reparse/hard-link rejection and an exclusive current-process/SYSTEM
DACL.  Artifact transport and task coordination remain in their shared
components.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re


MAX_DPAPI_BYTES = 64 * 1024


class ProtectedStateError(RuntimeError):
    """Closed failure for local protected-state primitives."""


class _Blob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def no_reparse(path: Path) -> None:
    """Reject symlinks/reparse points and multiply linked regular files."""

    selected = Path(path)
    try:
        for current in (selected, *selected.parents):
            info = current.lstat()
            if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ProtectedStateError("reparse_path_blocked")
        if selected.is_file() and selected.stat().st_nlink != 1:
            raise ProtectedStateError("hardlink_path_blocked")
    except ProtectedStateError:
        raise
    except OSError:
        raise ProtectedStateError("protected_path_unavailable") from None


def dpapi(data: bytes, *, encrypt: bool) -> bytes:
    """Use CurrentUser DPAPI with all UI forbidden and no machine scope."""

    if os.name != "nt":
        raise ProtectedStateError("dpapi_windows_required")
    if type(data) is not bytes or not data or len(data) > MAX_DPAPI_BYTES:
        raise ProtectedStateError("dpapi_input_invalid")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    input_buffer = ctypes.create_string_buffer(data)
    input_blob = _Blob(
        len(data),
        ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    output_blob = _Blob()
    if encrypt:
        procedure = crypt.CryptProtectData
        procedure.argtypes = [
            ctypes.POINTER(_Blob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_Blob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_Blob),
        ]
    else:
        procedure = crypt.CryptUnprotectData
        procedure.argtypes = [
            ctypes.POINTER(_Blob),
            ctypes.c_void_p,
            ctypes.POINTER(_Blob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_Blob),
        ]
    procedure.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        succeeded = procedure(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            0x1,  # CRYPTPROTECT_UI_FORBIDDEN; no LOCAL_MACHINE flag.
            ctypes.byref(output_blob),
        )
        if not succeeded or not output_blob.pbData or output_blob.cbData == 0:
            raise ProtectedStateError(
                "dpapi_protect_failed" if encrypt else "dpapi_unprotect_failed",
            )
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.memset(input_buffer, 0, len(input_buffer))
        if output_blob.pbData:
            kernel.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


class WindowsPrivateFiles:
    """Apply and verify a DACL for only the process identity and SYSTEM."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise ProtectedStateError("windows_acl_required")
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.advapi.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self.advapi.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.advapi.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi.SetFileSecurityW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self.advapi.GetFileSecurityW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.sid = self._user_sid()
        self.file_sddl = f"O:{self.sid}D:P(A;;FA;;;{self.sid})(A;;FA;;;SY)"
        self.directory_sddl = (
            f"O:{self.sid}D:P(A;OICI;FA;;;{self.sid})(A;OICI;FA;;;SY)"
        )

    def _canonical_sid(self, value: str) -> str:
        sid = ctypes.c_void_p()
        if not self.advapi.ConvertStringSidToSidW(value, ctypes.byref(sid)):
            raise ProtectedStateError("private_acl_sid_invalid")
        text = ctypes.c_void_p()
        try:
            if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise ProtectedStateError("private_acl_sid_invalid")
            try:
                return ctypes.wstring_at(text)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.LocalFree(sid)

    def _user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(
            self.kernel.GetCurrentProcess(),
            8,  # TOKEN_QUERY
            ctypes.byref(token),
        ):
            raise ProtectedStateError("private_acl_identity_failed")
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value or size.value > 64 * 1024:
                raise ProtectedStateError("private_acl_identity_failed")
            buffer = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(
                token,
                1,  # TokenUser
                buffer,
                size.value,
                ctypes.byref(size),
            ):
                raise ProtectedStateError("private_acl_identity_failed")
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            text = ctypes.c_void_p()
            if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise ProtectedStateError("private_acl_identity_failed")
            try:
                return ctypes.wstring_at(text)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.CloseHandle(token)

    def secure(self, path: Path) -> None:
        selected = Path(path)
        no_reparse(selected)
        descriptor = ctypes.c_void_p()
        sddl = self.directory_sddl if selected.is_dir() else self.file_sddl
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            1,
            ctypes.byref(descriptor),
            None,
        ):
            raise ProtectedStateError("private_acl_descriptor_failed")
        try:
            if not self.advapi.SetFileSecurityW(str(selected), 0x80000005, descriptor):
                raise ProtectedStateError("private_acl_write_failed")
        finally:
            self.kernel.LocalFree(descriptor)
        self.check(selected)

    def check(self, path: Path) -> None:
        selected = Path(path)
        no_reparse(selected)
        size = wintypes.DWORD()
        self.advapi.GetFileSecurityW(str(selected), 5, None, 0, ctypes.byref(size))
        if not size.value or size.value > 64 * 1024:
            raise ProtectedStateError("private_acl_read_failed")
        descriptor = ctypes.create_string_buffer(size.value)
        if not self.advapi.GetFileSecurityW(
            str(selected), 5, descriptor, size.value, ctypes.byref(size),
        ):
            raise ProtectedStateError("private_acl_read_failed")
        text = ctypes.c_void_p()
        if not self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 5, ctypes.byref(text), None,
        ):
            raise ProtectedStateError("private_acl_read_failed")
        try:
            value = ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)
        inheritance = r"(?:OICI)?" if selected.is_dir() else ""
        match = re.fullmatch(
            r"O:([^:]+)D:P(?:AI)?((?:\(A;"
            + inheritance
            + r";FA;;;[^)]+\)){2})",
            value,
        )
        if not match or self._canonical_sid(match.group(1)) != self._canonical_sid(self.sid):
            raise ProtectedStateError("private_acl_not_exclusive")
        identities = re.findall(
            r"\(A;" + inheritance + r";FA;;;([^)]+)\)",
            match.group(2),
        )
        actual = sorted(self._canonical_sid(identity) for identity in identities)
        expected = sorted((self._canonical_sid(self.sid), self._canonical_sid("SY")))
        if actual != expected:
            raise ProtectedStateError("private_acl_not_exclusive")
