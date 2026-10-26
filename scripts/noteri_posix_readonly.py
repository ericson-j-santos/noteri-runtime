"""Passive Noteri Ubuntu WSL2 diagnosis; never launches WSL or starts services.

Entry point is intended ONLY for an existing, authenticated POSIX
Session Launcher + Command Gateway session *inside an already-running* distro.
This script cannot authorize the transport or prove that distro startup was safe.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

HOST = "noteri"
DISTRO_PATTERN = re.compile(r"Ubuntu(?:-[0-9]{2}\.[0-9]{2})?\Z")
PSQL_VERSION = re.compile(r"psql \(PostgreSQL\) ([0-9]{1,2})(?:\.[0-9]{1,3})?(?:\s.*)?\Z")
PROBE_COMMANDS = (
    ("systemd", ("/usr/bin/systemctl", "is-system-running")),
    ("psql", ("/usr/bin/psql", "--version")),
    ("postgresql_service", ("/usr/bin/systemctl", "is-active", "postgresql.service")),
)
SYSTEMD_STATES = frozenset({
    "running", "degraded", "starting", "stopping", "maintenance",
    "initializing", "offline", "unknown",
})
SERVICE_STATES = frozenset({
    "active", "inactive", "failed", "activating", "deactivating", "unknown",
})
READ_PATHS = (
    "/proc/sys/kernel/osrelease",
    "/etc/os-release",
    "/proc/1/comm",
)


class Blocked(ValueError):
    """Sanitized failure code, never includes command output or private paths."""


def _read_fixed(path: str) -> str:
    if path not in READ_PATHS:
        raise Blocked("PATH_DENIED")
    try:
        with Path(path).open("rb") as stream:
            payload = stream.read(8193)
        if len(payload) > 8192:
            raise Blocked("SOURCE_TOO_LARGE")
        return payload.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise Blocked("SOURCE_UNAVAILABLE") from None


def _identity(platform_name: str, hostname: str, distro: str, read_text) -> bool:
    if platform_name != "linux" or type(hostname) is not str or hostname.casefold() != HOST:
        raise Blocked("NOTERI_LINUX_REQUIRED")
    if type(distro) is not str or DISTRO_PATTERN.fullmatch(distro) is None:
        raise Blocked("UBUNTU_DISTRO_REQUIRED")
    kernel = read_text(READ_PATHS[0]).casefold().strip()
    if "microsoft" not in kernel or "wsl2" not in kernel:
        raise Blocked("WSL2_KERNEL_REQUIRED")
    release = read_text(READ_PATHS[1]).splitlines()
    ids = [item[3:].strip() for item in release if item.startswith("ID=")]
    if len(ids) != 1 or ids[0] not in {"ubuntu", "'ubuntu'", '"ubuntu"'}:
        raise Blocked("UBUNTU_OS_RELEASE_REQUIRED")
    return read_text(READ_PATHS[2]).strip() == "systemd"


def _fixed_probe(name: str, runner) -> tuple[int, str]:
    matches = [command for key, command in PROBE_COMMANDS if key == name]
    if len(matches) != 1:
        raise Blocked("PROBE_NOT_ALLOWED")
    try:
        outcome = runner(
            list(matches[0]), shell=False, check=False, capture_output=True,
            text=True, timeout=5, cwd="/", close_fds=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("PROBE_UNAVAILABLE") from None
    if type(outcome.returncode) is not int or type(outcome.stdout) is not str:
        raise Blocked("PROBE_RESPONSE_INVALID")
    if len(outcome.stdout) > 512:
        raise Blocked("PROBE_OUTPUT_LIMIT")
    return outcome.returncode, outcome.stdout.strip()


def collect(
    *, platform_name=None, hostname=None, distro_name=None,
    read_text=None, run_command=None,
) -> dict:
    platform_name = sys.platform if platform_name is None else platform_name
    hostname = socket.gethostname() if hostname is None else hostname
    distro_name = os.getenv("WSL_DISTRO_NAME", "") if distro_name is None else distro_name
    read_text = _read_fixed if read_text is None else read_text
    run_command = subprocess.run if run_command is None else run_command
    pid1_systemd = _identity(platform_name, hostname, distro_name, read_text)

    result = {
        "result": "NOTERI_POSIX_PASSIVE_OBSERVED",
        "scope": "noteri_already_running_ubuntu_wsl2_only",
        "wsl2_ubuntu_observed": True,
        "systemd_pid1": pid1_systemd,
        "systemd_state": "unavailable",
        "psql_client_present": False,
        "psql_major": None,
        "postgresql_service_state": "unavailable",
        "postgresql_service_active": False,
        "linux_command_execution_observed": True,
        "gateway_session_verified": False,
        "distro_previously_running_verified": False,
        "wsl_launch_invoked": False,
        "service_start_invoked": False,
        "database_connection_attempted": False,
        "postgresql_connection_verified": False,
        "postgresql_tls_verified": False,
        "agent_qwen_autonomous_verified": False,
        "ready_for_postgresql": False,
    }

    if pid1_systemd:
        systemd_rc, systemd_output = _fixed_probe("systemd", run_command)
        result["systemd_state"] = (
            systemd_output if systemd_output in SYSTEMD_STATES and systemd_rc in (0, 1)
            else "unknown"
        )

    psql_rc, psql_output = _fixed_probe("psql", run_command)
    matched = PSQL_VERSION.fullmatch(psql_output) if psql_rc == 0 else None
    if matched:
        result["psql_client_present"] = True
        result["psql_major"] = int(matched.group(1))

    if pid1_systemd:
        service_rc, service_output = _fixed_probe("postgresql_service", run_command)
        if service_output in SERVICE_STATES and service_rc in (0, 1, 3, 4):
            result["postgresql_service_state"] = service_output
            result["postgresql_service_active"] = (
                service_output == "active" and service_rc == 0
            )
        else:
            result["postgresql_service_state"] = "unknown"

    return result


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise Blocked("ARGUMENTS_DENIED")
        print(json.dumps(collect(), sort_keys=True, separators=(",", ":")))
        return 0
    except (Blocked, OSError, ValueError):
        print(json.dumps({
            "result": "NOTERI_POSIX_PASSIVE_BLOCKED",
            "ready_for_postgresql": False,
            "agent_qwen_autonomous_verified": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
