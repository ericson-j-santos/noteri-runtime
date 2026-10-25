#!/usr/bin/env python3
"""Read only SQL Server startup TLS classifications from Windows Application events.

The public output is deliberately restricted to classification, date, and event ID.
No raw event XML, certificate material, paths, identities, or credentials are emitted.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import json
import os
import re
import socket
from typing import Any, Callable, Iterable

import noteri_native_qualification as native

CHANNEL = "Application"
PROVIDER = "MSSQLSERVER"
QUERY = "*[System[Provider[@Name='MSSQLSERVER']]]"
VALUE_PATHS = ("Event/System/EventID", "Event/System/TimeCreated/@SystemTime")
MAX_EVENTS = 64
MAX_MATCHES = 16
BATCH_SIZE = 8
TIMEOUT_MS = 2000
MAX_MESSAGE_CHARS = 16384

ERROR_ACCESS_DENIED = 5
ERROR_NO_MORE_ITEMS = 259
ERROR_TIMEOUT = 1460
EVT_QUERY_CHANNEL_PATH = 0x1
EVT_QUERY_REVERSE_DIRECTION = 0x200
EVT_RENDER_EVENT_VALUES = 0
EVT_FORMAT_MESSAGE_EVENT = 1
EVT_VAR_TYPE_MASK = 0x7F
EVT_VAR_TYPE_STRING = 1
EVT_VAR_TYPE_UINT16 = 6
EVT_VAR_TYPE_UINT32 = 8
EVT_VAR_TYPE_UINT64 = 10
EVT_VAR_TYPE_FILETIME = 17


class Blocked(ValueError):
    """A closed, non-sensitive reason that collection cannot proceed."""


class EventLogFailure(RuntimeError):
    def __init__(self, code: int):
        super().__init__(f"eventlog_error_{int(code)}")
        self.code = int(code)


class _VariantValue(ctypes.Union):
    _fields_ = [
        ("StringVal", wintypes.LPWSTR),
        ("UInt16Val", wintypes.WORD),
        ("UInt32Val", wintypes.DWORD),
        ("UInt64Val", ctypes.c_ulonglong),
        ("FileTimeVal", ctypes.c_ulonglong),
    ]


class _EvtVariant(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("value", _VariantValue),
        ("Count", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _last_error() -> int:
    return int(ctypes.get_last_error())


def _raise_last_error() -> None:
    raise EventLogFailure(_last_error())


def _iso_date(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _filetime_date(value: Any) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    try:
        parsed = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=value // 10
        )
    except (OverflowError, ValueError):
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def classify_message(message: Any) -> str | None:
    if not isinstance(message, str):
        return None
    low = message[:MAX_MESSAGE_CHARS].casefold()
    if "a self-generated certificate was successfully loaded for encryption" in low:
        return "self_generated_certificate_loaded"
    if "the certificate [cert hash(sha1)" in low and "was successfully loaded for encryption" in low:
        return "store_certificate_loaded"
    if "unable to load user-specified certificate" in low:
        return "configured_certificate_load_failed"
    if "server could not load the certificate" in low:
        return "certificate_load_failed"
    if "unable to initialize ssl encryption" in low:
        return "encryption_initialization_failed"
    return None


def _minimal(classification: str, date: str | None = None, event_id: int = 0) -> dict[str, Any]:
    return {"classification": classification, "date": date, "id": int(event_id)}


class WindowsEventReader:
    """Bounded wevtapi reader with a fixed channel, provider and value paths."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise EventLogFailure(120)
        self._dll = ctypes.WinDLL("wevtapi.dll", use_last_error=True)
        self._configure()
        self._query = None
        self._render_context = None
        self._publisher = None

    def _configure(self) -> None:
        handle = wintypes.HANDLE
        self._dll.EvtQuery.argtypes = [handle, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        self._dll.EvtQuery.restype = handle
        self._dll.EvtNext.argtypes = [
            handle, wintypes.DWORD, ctypes.POINTER(handle), wintypes.DWORD,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        self._dll.EvtNext.restype = wintypes.BOOL
        self._dll.EvtCreateRenderContext.argtypes = [
            wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR), wintypes.DWORD,
        ]
        self._dll.EvtCreateRenderContext.restype = handle
        self._dll.EvtRender.argtypes = [
            handle, handle, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        self._dll.EvtRender.restype = wintypes.BOOL
        self._dll.EvtOpenPublisherMetadata.argtypes = [
            handle, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ]
        self._dll.EvtOpenPublisherMetadata.restype = handle
        self._dll.EvtFormatMessage.argtypes = [
            handle, handle, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        ]
        self._dll.EvtFormatMessage.restype = wintypes.BOOL
        self._dll.EvtClose.argtypes = [handle]
        self._dll.EvtClose.restype = wintypes.BOOL

    def _open(self) -> None:
        flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION
        self._query = self._dll.EvtQuery(None, CHANNEL, QUERY, flags)
        if not self._query:
            _raise_last_error()
        paths = (wintypes.LPCWSTR * len(VALUE_PATHS))(*VALUE_PATHS)
        self._render_context = self._dll.EvtCreateRenderContext(len(VALUE_PATHS), paths, 0)
        if not self._render_context:
            _raise_last_error()
        self._publisher = self._dll.EvtOpenPublisherMetadata(None, PROVIDER, None, 0, 0)
        if not self._publisher:
            _raise_last_error()

    def _render_values(self, event: Any) -> tuple[int, str | None]:
        used = wintypes.DWORD()
        count = wintypes.DWORD()
        self._dll.EvtRender(
            self._render_context, event, EVT_RENDER_EVENT_VALUES, 0, None,
            ctypes.byref(used), ctypes.byref(count),
        )
        code = _last_error()
        if code != 122 or used.value == 0:
            raise EventLogFailure(code)
        buffer = ctypes.create_string_buffer(used.value)
        if not self._dll.EvtRender(
            self._render_context, event, EVT_RENDER_EVENT_VALUES, used.value, buffer,
            ctypes.byref(used), ctypes.byref(count),
        ):
            _raise_last_error()
        if count.value != len(VALUE_PATHS):
            raise EventLogFailure(13)
        values = ctypes.cast(buffer, ctypes.POINTER(_EvtVariant))
        kind = values[0].Type & EVT_VAR_TYPE_MASK
        if kind == EVT_VAR_TYPE_UINT16:
            event_id = int(values[0].UInt16Val)
        elif kind == EVT_VAR_TYPE_UINT32:
            event_id = int(values[0].UInt32Val)
        elif kind == EVT_VAR_TYPE_UINT64:
            event_id = int(values[0].UInt64Val)
        else:
            raise EventLogFailure(13)
        date_kind = values[1].Type & EVT_VAR_TYPE_MASK
        if date_kind == EVT_VAR_TYPE_STRING:
            date = values[1].StringVal
        elif date_kind == EVT_VAR_TYPE_FILETIME:
            date = _filetime_date(int(values[1].FileTimeVal))
        else:
            date = None
        return event_id, date

    def _format_message(self, event: Any) -> str:
        used = wintypes.DWORD()
        self._dll.EvtFormatMessage(
            self._publisher, event, 0, 0, None, EVT_FORMAT_MESSAGE_EVENT,
            0, None, ctypes.byref(used),
        )
        code = _last_error()
        if code != 122 or used.value == 0 or used.value > MAX_MESSAGE_CHARS + 1:
            raise EventLogFailure(code if code != 122 else 13)
        buffer = ctypes.create_unicode_buffer(used.value)
        if not self._dll.EvtFormatMessage(
            self._publisher, event, 0, 0, None, EVT_FORMAT_MESSAGE_EVENT,
            used.value, buffer, ctypes.byref(used),
        ):
            _raise_last_error()
        return buffer.value[:MAX_MESSAGE_CHARS]

    def iter_events(self) -> Iterable[dict[str, Any]]:
        self._open()
        handles = (wintypes.HANDLE * BATCH_SIZE)()
        seen = 0
        while seen < MAX_EVENTS:
            returned = wintypes.DWORD()
            if not self._dll.EvtNext(
                self._query, min(BATCH_SIZE, MAX_EVENTS - seen), handles,
                TIMEOUT_MS, 0, ctypes.byref(returned),
            ):
                code = _last_error()
                if code == ERROR_NO_MORE_ITEMS:
                    return
                raise EventLogFailure(code)
            if returned.value == 0:
                return
            batch = []
            try:
                for index in range(returned.value):
                    event = handles[index]
                    try:
                        event_id, date = self._render_values(event)
                        message = self._format_message(event)
                        batch.append({"id": event_id, "date": date, "message": message})
                    finally:
                        self._dll.EvtClose(event)
                        handles[index] = None
                    seen += 1
                    if seen >= MAX_EVENTS:
                        break
            finally:
                for index in range(returned.value):
                    event = handles[index]
                    if event:
                        self._dll.EvtClose(event)
                        handles[index] = None
            yield from batch
            if seen >= MAX_EVENTS:
                return

    def close(self) -> None:
        for name in ("_publisher", "_render_context", "_query"):
            handle = getattr(self, name, None)
            if handle:
                self._dll.EvtClose(handle)
                setattr(self, name, None)


def _validate_host(expected_sha: str) -> None:
    if os.name != "nt" or socket.gethostname().casefold() != "noteri":
        raise Blocked("noteri_windows_required")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise Blocked("source_sha_invalid")
    native.source_head(expected_sha)
    profile = native.profile()
    if profile.get("verified") is not True or profile.get("profile") != "NORMAL":
        raise Blocked("normal_profile_required")
    sql = native.sql_inventory()
    valid = any(
        isinstance(item, dict)
        and item.get("instance") == PROVIDER
        and item.get("service_state") == "running"
        and str(item.get("installed_version", "")).startswith("17.")
        for item in sql.get("instances", [])
    )
    if sql.get("status") != "observed" or not valid:
        raise Blocked("local_sql2025_not_running")


def collect(
    expected_sha: str,
    reader_factory: Callable[[], Any] = WindowsEventReader,
) -> list[dict[str, Any]]:
    _validate_host(expected_sha)
    reader = reader_factory()
    matches: list[dict[str, Any]] = []
    try:
        for event in reader.iter_events():
            classification = classify_message(event.get("message"))
            date = _iso_date(event.get("date"))
            event_id = event.get("id")
            if classification is None or date is None:
                continue
            if not isinstance(event_id, int) or isinstance(event_id, bool) or not (0 < event_id <= 0xFFFFFFFF):
                continue
            matches.append(_minimal(classification, date, event_id))
            if len(matches) >= MAX_MATCHES:
                break
    finally:
        reader.close()
    return matches or [_minimal("not_observed")]


def _failure_output(exc: BaseException) -> list[dict[str, Any]]:
    code = getattr(exc, "winerror", None)
    if code is None:
        code = getattr(exc, "errno", None)
    if isinstance(exc, EventLogFailure):
        code = exc.code
    if code == ERROR_ACCESS_DENIED:
        return [_minimal("eventlog_access_denied")]
    if code == ERROR_TIMEOUT:
        return [_minimal("eventlog_timeout")]
    if isinstance(exc, (Blocked, native.Blocked)):
        allowed = {
            "noteri_windows_required", "source_sha_invalid", "source_sha_mismatch",
            "normal_profile_required", "local_sql2025_not_running",
        }
        return [_minimal(str(exc) if str(exc) in allowed else "eventlog_unavailable")]
    return [_minimal("eventlog_unavailable")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args(argv)
    try:
        output = collect(args.expected_sha)
        code = 0
    except Exception as exc:
        output = _failure_output(exc)
        code = 2
    print(json.dumps(output, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
