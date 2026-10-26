"""Positive, negative, drift and replay tests for Noteri WSL registration readback.

This test emulates HKCU metadata only. It never starts WSL or PostgreSQL.
Hardware/WSL/systemd/TLS readiness requires a separate governed physical gate.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from scripts import noteri_wsl_registration_readonly as probe

ONE = "{11111111-1111-4111-8111-111111111111}"
TWO = "{22222222-2222-4222-8222-222222222222}"


class FakeKey:
    def __init__(self, values=None, children=None):
        self.values = values or {}
        self.children = children or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeReg:
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 0x20019
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self, entries=None, default=ONE, *, exists=True):
        self.root = FakeKey(
            {} if default is None else {"DefaultDistribution": (default, self.REG_SZ)},
            entries or {},
        )
        self.exists = exists
        self.requests = []

    def OpenKey(self, key, path, reserved=0, access=None):
        self.requests.append((path, reserved, access))
        assert reserved == 0
        assert access == self.KEY_READ
        if key == self.HKEY_CURRENT_USER and path == probe.KEY:
            if not self.exists:
                raise FileNotFoundError()
            return self.root
        if key is self.root and path in self.root.children:
            return self.root.children[path]
        raise FileNotFoundError()

    def QueryInfoKey(self, key):
        assert key is self.root
        return len(key.children), 0, 0

    def EnumKey(self, key, n):
        assert key is self.root
        return list(key.children)[n]

    def QueryValueEx(self, key, name):
        # Deliberately deny BasePath, keys/locations/secrets.
        assert name in ("DefaultDistribution", "Version", "DistributionName")
        if name not in key.values:
            raise FileNotFoundError()
        return key.values[name]


def child(version, name, *, kind=None):
    result = {}
    if version is not None:
        result["Version"] = (version, FakeReg.REG_DWORD if kind is None else kind)
    if name is not None:
        result["DistributionName"] = (name, FakeReg.REG_SZ)
    return FakeKey(result)


def measure(reg):
    return probe.collect(reg, platform_name="win32", hostname="Noteri")


def test_two_registered_distros_are_only_candidates_not_postgres_evidence():
    reg = FakeReg({ONE: child(2, "Ubuntu-24.04"), TWO: child(1, "Debian")})
    first, second = measure(reg), measure(reg)
    assert first == second
    assert first["distro_count"] == 2 and first["wsl2_count"] == 1
    assert first["default_wsl2_candidate"] is True
    assert first["distributions"] == [
        {"alias": "distro-1", "wsl_version": 2, "family": "ubuntu",
         "default": True, "state": "unknown"},
        {"alias": "distro-2", "wsl_version": 1, "family": "debian",
         "default": False, "state": "unknown"},
    ]
    assert first["scope"] == "current_windows_token_hkcu_only"
    assert first["linux_started"] is False
    assert first["systemd_verified"] is False
    assert first["postgresql_service_verified"] is False
    assert first["postgresql_tls_verified"] is False
    assert first["shared_authority_verified"] is False
    assert first["ready_for_pr"] is False
    assert first["credentials_read"] is False and first["state_changed"] is False
    assert all(access == reg.KEY_READ for _, _, access in reg.requests)


def test_absent_wsl_registration_is_not_general_host_absence():
    report = measure(FakeReg(exists=False))
    assert report["distro_count"] == report["wsl2_count"] == 0
    assert report["default_wsl2_candidate"] is False
    assert report["scope"] == "current_windows_token_hkcu_only"
    assert report["ready_for_pr"] is False


@pytest.mark.parametrize("reg,code", [
    (FakeReg({ONE: child(3, "Ubuntu")}), "WSL_VERSION_INVALID"),
    (FakeReg({ONE: child(True, "Ubuntu")}), "WSL_VERSION_INVALID"),
    (FakeReg({ONE: child(2, "Ubuntu", kind=FakeReg.REG_SZ)}),
     "WSL_VERSION_INVALID"),
    (FakeReg({"../evil": child(2, "Ubuntu")}), "WSL_REGISTRATION_INVALID"),
    (FakeReg({ONE: child(2, "X" * 129)}), "WSL_NAME_SHAPE_INVALID"),
    (FakeReg({ONE: child(2, "Ubuntu")}, default="wrong"),
     "WSL_DEFAULT_INVALID"),
    (FakeReg({f"{{{i:08x}-1111-4111-8111-111111111111}}": child(2, "Ubuntu")
              for i in range(17)}), "WSL_REGISTRATION_LIMIT"),
])
def test_invalid_metadata_fails_closed_without_leaking_identity(reg, code):
    with pytest.raises(probe.Blocked, match="^" + code + "$"):
        measure(reg)


def test_default_registered_but_non_posix_or_wsl1_is_not_candidate():
    assert measure(FakeReg({ONE: child(1, "Ubuntu")}))["default_wsl2_candidate"] is False
    assert measure(FakeReg({ONE: child(2, "Unknown Linux")}))["default_wsl2_candidate"] is False
    assert measure(FakeReg({ONE: child(2, "Debian")}, default=None))["default_wsl2_candidate"] is False


def test_registry_disappearing_mid_probe_is_blocked_not_accepted_as_absent():
    class Inconsistent(FakeReg):
        def OpenKey(self, key, path, reserved=0, access=None):
            if key is self.root:
                raise FileNotFoundError()
            return super().OpenKey(key, path, reserved, access)
    with pytest.raises(probe.Blocked, match="WSL_REGISTRY_INCONSISTENT"):
        measure(Inconsistent({ONE: child(2, "Ubuntu")}))


@pytest.mark.parametrize("host,platform", [
    ("DESKTOP-PDQK954", "win32"), ("Noteri", "linux"), ("", "win32"),
])
def test_wrong_host_or_platform_fails_closed_before_registry_access(host, platform):
    reg = FakeReg({ONE: child(2, "Ubuntu")})
    with pytest.raises(probe.Blocked, match="NOTERI_WINDOWS_REQUIRED"):
        probe.collect(reg, platform_name=platform, hostname=host)
    assert reg.requests == []


def test_source_has_no_linux_launch_or_postgres_connection_calls():
    source = Path(probe.__file__).read_text(encoding="utf-8")
    for prohibited in ("import subprocess", "os.system(", "Popen(", "subprocess.run(",
                       "winreg.SetValue", "winreg.CreateKey", "winreg.DeleteKey",
                       "QueryValueEx(child, \"BasePath\")", "urllib.request",
                       "psycopg.connect(", "sqlite3.connect("):
        assert prohibited not in source
    # Read-only registry current token; nowhere do tests mark the host ready.
    assert "reg.HKEY_CURRENT_USER" in source and "reg.KEY_READ" in source
    assert '"ready_for_pr": False' in source
