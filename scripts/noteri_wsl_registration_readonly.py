"""Read-only WSL registration inventory for the Noteri control-plane token.

Never invokes wsl.exe, starts a distro, opens Linux files, reads BasePath,
connects to PostgreSQL, or changes host configuration. Windows HKCU only:
registration is NOT proof of a running Linux/systemd/PostgreSQL authority.
"""
from __future__ import annotations

import json
import re
import socket
import sys

try:
    import winreg
except ImportError:  # Deterministic cross-platform unit tests
    winreg = None

HOST = "noteri"
KEY = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
MAX_DISTROS = 16
GUID = re.compile(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?\Z")


class Blocked(ValueError):
    """A constant safe rejection reason; never contains a registry value."""


def _family(name: str) -> str:
    if type(name) is not str or len(name) > 128:
        raise Blocked("WSL_NAME_SHAPE_INVALID")
    lower = name.casefold()
    if lower.startswith("ubuntu"):
        return "ubuntu"
    if lower.startswith("debian"):
        return "debian"
    return "other"


def _empty() -> dict:
    return {
        "result": "NOTERI_WSL_REGISTRATION_READONLY",
        "scope": "current_windows_token_hkcu_only",
        "distro_count": 0,
        "wsl2_count": 0,
        "default_wsl2_candidate": False,
        "distributions": [],
        "wsl_process_launched": False,
        "linux_started": False,
        "systemd_verified": False,
        "postgresql_service_verified": False,
        "postgresql_tls_verified": False,
        "shared_authority_verified": False,
        "backup_restore_verified": False,
        "credentials_read": False,
        "state_changed": False,
        "ready_for_pr": False,
    }


def collect(registry=None, *, platform_name=None, hostname=None) -> dict:
    platform_name = sys.platform if platform_name is None else platform_name
    hostname = socket.gethostname() if hostname is None else hostname
    if platform_name != "win32" or type(hostname) is not str or hostname.casefold() != HOST:
        raise Blocked("NOTERI_WINDOWS_REQUIRED")
    reg = winreg if registry is None else registry
    if reg is None:
        raise Blocked("WINREG_UNAVAILABLE")

    report = _empty()
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, KEY, 0, reg.KEY_READ) as root:
            count = reg.QueryInfoKey(root)[0]
            if type(count) is not int or not 0 <= count <= MAX_DISTROS:
                raise Blocked("WSL_REGISTRATION_LIMIT")
            try:
                default, kind = reg.QueryValueEx(root, "DefaultDistribution")
            except FileNotFoundError:
                default, kind = None, None
            if default is not None and (type(default) is not str or
                                        kind != reg.REG_SZ or
                                        GUID.fullmatch(default) is None):
                raise Blocked("WSL_DEFAULT_INVALID")

            used = set()
            distros = []
            for number in range(count):
                identity = reg.EnumKey(root, number)
                if (type(identity) is not str or GUID.fullmatch(identity) is None or
                        identity.casefold() in used):
                    raise Blocked("WSL_REGISTRATION_INVALID")
                used.add(identity.casefold())
                with reg.OpenKey(root, identity, 0, reg.KEY_READ) as child:
                    try:
                        version, version_kind = reg.QueryValueEx(child, "Version")
                    except FileNotFoundError:
                        version, version_kind = None, None
                    try:
                        name, name_kind = reg.QueryValueEx(child, "DistributionName")
                    except FileNotFoundError:
                        name, name_kind = "", None
                if (version is not None and
                        (type(version) is not int or version_kind != reg.REG_DWORD or
                         version not in (1, 2))):
                    raise Blocked("WSL_VERSION_INVALID")
                if name_kind not in (reg.REG_SZ, None):
                    raise Blocked("WSL_NAME_SHAPE_INVALID")
                family = _family(name)
                distros.append({
                    "alias": "distro-" + str(number + 1),
                    "wsl_version": version,
                    "family": family,
                    "default": identity.casefold() == (default or "").casefold(),
                    "state": "unknown",
                })
    except FileNotFoundError:
        return report
    except (OSError, TypeError, ValueError, IndexError) as exc:
        if isinstance(exc, Blocked):
            raise
        raise Blocked("WSL_REGISTRY_READ_UNAVAILABLE") from None

    report["distro_count"] = len(distros)
    report["wsl2_count"] = sum(v["wsl_version"] == 2 for v in distros)
    report["default_wsl2_candidate"] = any(
        v["default"] and v["wsl_version"] == 2 and
        v["family"] in ("ubuntu", "debian") for v in distros
    )
    report["distributions"] = distros
    return report


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise Blocked("ARGUMENTS_DENIED")
        report = collect()
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (Blocked, OSError, ValueError):
        print(json.dumps({
            "result": "NOTERI_WSL_REGISTRATION_BLOCKED",
            "state_changed": False,
            "ready_for_pr": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
