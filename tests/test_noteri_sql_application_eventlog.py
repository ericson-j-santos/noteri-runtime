"""Fixture-only tests for the minimized SQL Application EventLog collector."""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

SRC = Path(__file__).resolve().parents[1] / "scripts" / "noteri_sql_application_eventlog.py"


class NativeBlocked(ValueError):
    pass


native = types.ModuleType("noteri_native_qualification")
native.Blocked = NativeBlocked
native.source_head = lambda sha: sha
native.profile = lambda: {"profile": "NORMAL", "verified": True}
native.sql_inventory = lambda: {
    "status": "observed",
    "instances": [{
        "instance": "MSSQLSERVER",
        "installed_version": "17.0.1000.7",
        "service_state": "running",
    }],
}
with patch.dict(sys.modules, {"noteri_native_qualification": native}):
    spec = importlib.util.spec_from_file_location("eventlogtest", SRC)
    assert spec and spec.loader
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)


class FakeReader:
    def __init__(self, events=(), error=None):
        self.events = list(events)
        self.error = error
        self.closed = False

    def iter_events(self):
        if self.error is not None:
            raise self.error
        yield from self.events

    def close(self):
        self.closed = True


def valid_event(message, event_id=26017, date="2026-10-25T19:20:21.1234567Z"):
    return {"message": message, "id": event_id, "date": date}


@pytest.fixture
def host_ok():
    with patch.object(m.os, "name", "nt"), patch.object(
        m.socket, "gethostname", return_value="Noteri"
    ):
        yield


@pytest.mark.parametrize(
    "message,classification",
    [
        (
            "A self-generated certificate was successfully loaded for encryption.",
            "self_generated_certificate_loaded",
        ),
        (
            'The certificate [Cert Hash(sha1) "PRIVATE-HASH"] was successfully loaded for encryption.',
            "store_certificate_loaded",
        ),
        (
            "Unable to load user-specified certificate PRIVATE-CERT",
            "configured_certificate_load_failed",
        ),
        (
            "The server could not load the certificate PRIVATE-CERT",
            "certificate_load_failed",
        ),
        (
            "Unable to initialize SSL encryption PRIVATE-DETAIL",
            "encryption_initialization_failed",
        ),
    ],
)
def test_known_messages_are_classified_without_copying_message(message, classification):
    assert m.classify_message(message) == classification
    assert "PRIVATE" not in classification


@pytest.mark.parametrize(
    "message",
    [
        "Server listening on PRIVATE-HOST",
        "Login failed for PRIVATE-USER",
        "certificate rotation complete",
        None,
        42,
    ],
)
def test_unrelated_or_invalid_messages_are_not_emitted(message):
    assert m.classify_message(message) is None


def test_date_is_normalized_to_utc_and_invalid_dates_are_rejected():
    assert m._iso_date("2026-10-25T20:00:00+02:00") == "2026-10-25T18:00:00Z"
    assert m._iso_date("2026-10-25T18:00:00Z") == "2026-10-25T18:00:00Z"
    assert m._iso_date("PRIVATE-DATE") is None
    assert m._iso_date(None) is None


def test_filetime_parser_is_bounded_and_utc():
    epoch_2026 = 116444736000000000 + 1761436800 * 10_000_000
    assert m._filetime_date(epoch_2026) == "2025-10-26T00:00:00Z"
    assert m._filetime_date(-1) is None
    assert m._filetime_date("PRIVATE") is None


def test_fixture_collection_has_only_requested_fields_and_redacts_message(host_ok):
    reader = FakeReader([
        valid_event(
            'The certificate [Cert Hash(sha1) "PRIVATE-HASH"] was successfully loaded '
            "for encryption. PRIVATE-PATH"
        )
    ])
    result = m.collect("a" * 40, lambda: reader)
    assert result == [{
        "classification": "store_certificate_loaded",
        "date": "2026-10-25T19:20:21.123456Z",
        "id": 26017,
    }]
    assert set(result[0]) == {"classification", "date", "id"}
    assert "PRIVATE" not in json.dumps(result)
    assert reader.closed is True


def test_multiple_fixture_matches_are_bounded(host_ok):
    events = [
        valid_event(
            "A self-generated certificate was successfully loaded for encryption.",
            event_id=index + 1,
        )
        for index in range(m.MAX_MATCHES + 8)
    ]
    reader = FakeReader(events)
    result = m.collect("a" * 40, lambda: reader)
    assert len(result) == m.MAX_MATCHES
    assert reader.closed is True


def test_absence_returns_one_minimal_classification(host_ok):
    reader = FakeReader([valid_event("Server listening on PRIVATE-HOST")])
    assert m.collect("a" * 40, lambda: reader) == [{
        "classification": "not_observed",
        "date": None,
        "id": 0,
    }]
    assert reader.closed is True


@pytest.mark.parametrize(
    "error,classification",
    [
        (m.EventLogFailure(m.ERROR_ACCESS_DENIED), "eventlog_access_denied"),
        (m.EventLogFailure(m.ERROR_TIMEOUT), "eventlog_timeout"),
        (OSError(5, "PRIVATE"), "eventlog_access_denied"),
        (RuntimeError("PRIVATE"), "eventlog_unavailable"),
        (NativeBlocked("source_sha_mismatch"), "source_sha_mismatch"),
    ],
)
def test_failures_map_to_minimal_closed_classification(error, classification):
    result = m._failure_output(error)
    assert result == [{"classification": classification, "date": None, "id": 0}]
    assert "PRIVATE" not in json.dumps(result)


def test_reader_is_closed_when_iteration_fails(host_ok):
    reader = FakeReader(error=m.EventLogFailure(m.ERROR_TIMEOUT))
    with pytest.raises(m.EventLogFailure):
        m.collect("a" * 40, lambda: reader)
    assert reader.closed is True


@pytest.mark.parametrize(
    "event",
    [
        valid_event(
            "A self-generated certificate was successfully loaded for encryption.",
            event_id=True,
        ),
        valid_event(
            "A self-generated certificate was successfully loaded for encryption.",
            event_id=0,
        ),
        valid_event(
            "A self-generated certificate was successfully loaded for encryption.",
            event_id=2**32,
        ),
        valid_event(
            "A self-generated certificate was successfully loaded for encryption.",
            date="PRIVATE-DATE",
        ),
    ],
)
def test_invalid_id_or_date_is_skipped(host_ok, event):
    assert m.collect("a" * 40, lambda: FakeReader([event]))[0]["classification"] == "not_observed"


def test_wrong_host_and_invalid_sha_block_before_reader():
    make = lambda: (_ for _ in ()).throw(AssertionError("reader must not open"))
    with patch.object(m.os, "name", "nt"), patch.object(
        m.socket, "gethostname", return_value="GS"
    ):
        with pytest.raises(m.Blocked, match="noteri_windows_required"):
            m.collect("a" * 40, make)
    with patch.object(m.os, "name", "nt"), patch.object(
        m.socket, "gethostname", return_value="Noteri"
    ):
        with pytest.raises(m.Blocked, match="source_sha_invalid"):
            m.collect("bad", make)


def test_profile_and_sql_guards_block_before_reader(host_ok):
    make = lambda: (_ for _ in ()).throw(AssertionError("reader must not open"))
    with patch.object(native, "profile", return_value={"profile": "ESTUDO", "verified": True}):
        with pytest.raises(m.Blocked, match="normal_profile_required"):
            m.collect("a" * 40, make)
    with patch.object(native, "sql_inventory", return_value={"status": "observed", "instances": []}):
        with pytest.raises(m.Blocked, match="local_sql2025_not_running"):
            m.collect("a" * 40, make)


def test_fake_event_batch_closes_all_handles_before_first_yield():
    class FakeDll:
        def __init__(self):
            self.closed = []

        def EvtNext(self, query, count, handles, timeout, flags, returned):
            assert query == 1
            assert count == 2
            assert timeout == m.TIMEOUT_MS
            assert flags == 0
            handles[0] = 101
            handles[1] = 102
            returned._obj.value = 2
            return True

        def EvtClose(self, handle):
            self.closed.append(int(handle))
            return True

    dll = FakeDll()
    reader = object.__new__(m.WindowsEventReader)
    reader._dll = dll
    reader._query = 1
    reader._open = lambda: None
    reader._render_values = lambda event: (
        int(event),
        "2026-10-25T19:20:21Z",
    )
    reader._format_message = lambda event: (
        "A self-generated certificate was successfully loaded for encryption."
    )
    with patch.object(m, "MAX_EVENTS", 2), patch.object(m, "BATCH_SIZE", 2):
        stream = iter(reader.iter_events())
        first = next(stream)
        assert dll.closed == [101, 102]
        assert first["id"] == 101
        assert next(stream)["id"] == 102
        with pytest.raises(StopIteration):
            next(stream)


def test_fake_event_batch_closes_remaining_handles_on_parser_error():
    class FakeDll:
        def __init__(self):
            self.closed = []

        def EvtNext(self, query, count, handles, timeout, flags, returned):
            handles[0] = 201
            handles[1] = 202
            returned._obj.value = 2
            return True

        def EvtClose(self, handle):
            self.closed.append(int(handle))
            return True

    dll = FakeDll()
    reader = object.__new__(m.WindowsEventReader)
    reader._dll = dll
    reader._query = 1
    reader._open = lambda: None

    def fail_first(event):
        raise m.EventLogFailure(13)

    reader._render_values = fail_first
    reader._format_message = lambda event: "not reached"
    with patch.object(m, "MAX_EVENTS", 2), patch.object(m, "BATCH_SIZE", 2):
        stream = iter(reader.iter_events())
        with pytest.raises(m.EventLogFailure):
            next(stream)
    assert dll.closed == [201, 202]


def test_query_contract_is_fixed_and_bounded():
    assert m.CHANNEL == "Application"
    assert m.PROVIDER == "MSSQLSERVER"
    assert m.QUERY == "*[System[Provider[@Name='MSSQLSERVER']]]"
    assert m.VALUE_PATHS == (
        "Event/System/EventID",
        "Event/System/TimeCreated/@SystemTime",
    )
    assert 0 < m.BATCH_SIZE <= m.MAX_EVENTS <= 64
    assert 0 < m.TIMEOUT_MS <= 2000
    assert 0 < m.MAX_MATCHES <= m.MAX_EVENTS
    assert 0 < m.MAX_MESSAGE_CHARS <= 16384


def test_source_has_no_full_log_or_mutating_fallbacks():
    code = SRC.read_text(encoding="utf-8")
    forbidden = (
        "subprocess",
        "wevtutil",
        "powershell",
        "Get-WinEvent",
        "EvtRenderEventXml",
        "winreg",
        "SetValueEx",
        "Popen(",
        "os.system(",
        "shell=True",
        "TrustServerCertificate=Yes",
        "Encrypt=No",
    )
    for item in forbidden:
        assert item not in code
    secret_markers = (
        ("AK", "IA"),
        ("password", "="),
        ("api_key", "="),
        ("BEGIN ", "PRIVATE KEY"),
    )
    for left, right in secret_markers:
        assert left + right not in code
    assert "EvtFormatMessage" in code
    assert "EvtCreateRenderContext" in code


def test_replay_is_deterministic_and_message_length_is_bounded(host_ok):
    message = (
        "A self-generated certificate was successfully loaded for encryption."
        + "PRIVATE" * (m.MAX_MESSAGE_CHARS + 10)
    )
    event = valid_event(message)
    first = m.collect("a" * 40, lambda: FakeReader([event]))
    second = m.collect("a" * 40, lambda: FakeReader([event]))
    assert first == second
    assert "PRIVATE" not in json.dumps(first)


def test_main_serializes_only_minimal_output(capsys):
    expected = [{"classification": "not_observed", "date": None, "id": 0}]
    with patch.object(m, "collect", return_value=expected):
        assert m.main(["--expected-sha", "a" * 40]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value == expected
    assert set(value[0]) == {"classification", "date", "id"}


def test_main_sanitizes_unexpected_exception(capsys):
    with patch.object(m, "collect", side_effect=RuntimeError("PRIVATE-DETAIL")):
        assert m.main(["--expected-sha", "a" * 40]) == 2
    output = capsys.readouterr().out
    assert "PRIVATE" not in output
    assert json.loads(output) == [{
        "classification": "eventlog_unavailable",
        "date": None,
        "id": 0,
    }]
