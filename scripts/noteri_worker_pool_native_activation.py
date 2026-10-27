#!/usr/bin/env python3
"""Register the pinned Noteri Worker Pool API as a limited S4U boot task."""
from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import json
import os
import site
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import winreg
except ImportError:  # Unit tests may run off Windows; activation still checks os.name.
    winreg = None

from scripts import noteri_worker_pool_credential_reference as reference
from scripts import noteri_worker_pool_native_stage as stage
from scripts import noteri_worker_pool_native_venv as venv
from scripts import noteri_worker_pool_control_package as control

TASK_NAME = r"\Automation\NoteriWorkerPoolApi"
CONFIRM = "ACTIVATE-NOTERI-WORKER-POOL-API"
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
RUNNER_FILES = ("noteri_worker_pool_api_runner.py", "noteri_worker_pool_native_stage.py")


class Blocked(RuntimeError):
    pass


def is_admin() -> bool:
    try:
        return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def task_absent(windir: Path) -> bool:
    if winreg is None:
        return False
    folder = windir / "System32" / "Tasks" / "Automation"
    try:
        names = {item.name.casefold() for item in os.scandir(folder)}
    except OSError:
        return False
    if "noteriworkerpoolapi" in names:
        return False
    key = (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
           r"\Tree\Automation\NoteriWorkerPoolApi")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ):
            return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def listener_absent() -> bool:
    try:
        library = ctypes.WinDLL("iphlpapi")
        method = library.GetExtendedTcpTable
        method.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                           ctypes.c_bool, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        method.restype = ctypes.c_ulong
        size = ctypes.c_ulong(0)
        if method(None, ctypes.byref(size), False, 2, 5, 0) != 122:
            return False
        if not 4 <= size.value <= 1024 * 1024:
            return False
        buffer = ctypes.create_string_buffer(size.value)
        if method(buffer, ctypes.byref(size), False, 2, 5, 0) != 0:
            return False
        count = struct.unpack_from("<I", buffer, 0)[0]
        if 4 + count * 24 > size.value:
            return False
        for index in range(count):
            state, _address, port, _remote, _remote_port, _pid = struct.unpack_from(
                "<6I", buffer, 4 + index * 24)
            if state == 2 and socket.ntohs(port & 0xffff) == 8097:
                return False
        return True
    except (OSError, ValueError, struct.error):
        return False


def task_xml(python: Path, runner: Path, user: str) -> bytes:
    ET.register_namespace("", NS)
    task = ET.Element(f"{{{NS}}}Task", {"version": "1.4"})
    ET.SubElement(ET.SubElement(task, f"{{{NS}}}RegistrationInfo"),
                  f"{{{NS}}}Description").text = "Noteri Worker Pool API native loopback"
    triggers = ET.SubElement(task, f"{{{NS}}}Triggers")
    trigger = ET.SubElement(triggers, f"{{{NS}}}BootTrigger")
    ET.SubElement(trigger, f"{{{NS}}}Enabled").text = "true"
    ET.SubElement(trigger, f"{{{NS}}}Delay").text = "PT20S"
    principals = ET.SubElement(task, f"{{{NS}}}Principals")
    principal = ET.SubElement(principals, f"{{{NS}}}Principal", {"id": "Author"})
    for tag, value in (("UserId", user), ("LogonType", "S4U"),
                       ("RunLevel", "LeastPrivilege")):
        ET.SubElement(principal, f"{{{NS}}}{tag}").text = value
    settings = ET.SubElement(task, f"{{{NS}}}Settings")
    for tag, value in (("Enabled", "true"), ("StartWhenAvailable", "true"),
                       ("DisallowStartIfOnBatteries", "false"),
                       ("StopIfGoingOnBatteries", "false"),
                       ("MultipleInstancesPolicy", "IgnoreNew"),
                       ("ExecutionTimeLimit", "PT0S")):
        ET.SubElement(settings, f"{{{NS}}}{tag}").text = value
    actions = ET.SubElement(task, f"{{{NS}}}Actions", {"Context": "Author"})
    action = ET.SubElement(actions, f"{{{NS}}}Exec")
    ET.SubElement(action, f"{{{NS}}}Command").text = str(python)
    ET.SubElement(action, f"{{{NS}}}Arguments").text = f'-B "{runner}"'
    ET.SubElement(action, f"{{{NS}}}WorkingDirectory").text = str(runner.parent)
    return ET.tostring(task, encoding="utf-8", xml_declaration=True)


def account_sid(user: str) -> str:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    lookup = advapi.LookupAccountNameW
    lookup.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                       ctypes.POINTER(ctypes.c_ulong), ctypes.c_wchar_p,
                       ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    lookup.restype = ctypes.c_bool
    sid_size, domain_size, use = ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)
    lookup(None, user, None, ctypes.byref(sid_size), None,
           ctypes.byref(domain_size), ctypes.byref(use))
    if ctypes.get_last_error() != 122 or not 1 <= sid_size.value <= 256:
        raise Blocked("account_sid_unavailable")
    sid = ctypes.create_string_buffer(sid_size.value)
    domain = ctypes.create_unicode_buffer(max(1, domain_size.value))
    if not lookup(None, user, sid, ctypes.byref(sid_size), domain,
                  ctypes.byref(domain_size), ctypes.byref(use)):
        raise Blocked("account_sid_unavailable")
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    convert.restype = ctypes.c_bool
    value = ctypes.c_wchar_p()
    if not convert(sid, ctypes.byref(value)):
        raise Blocked("account_sid_unavailable")
    try:
        return value.value
    finally:
        ctypes.windll.kernel32.LocalFree(value)


def task_matches(raw: bytes, python: Path, runner: Path, user: str) -> bool:
    try:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            # schtasks /Query /XML emits UTF-8 bytes with a UTF-16 declaration.
            prefix = raw[:128]
            if not prefix.startswith(b'<?xml ') or b'encoding="UTF-16"' not in prefix:
                return False
            root = ET.fromstring(raw.replace(b'encoding="UTF-16"',
                                             b'encoding="UTF-8"', 1))
        get = lambda name: root.findtext(name, namespaces={"t": NS})
        observed_user = get("t:Principals/t:Principal/t:UserId")
        same_user = observed_user is not None and observed_user.casefold() == user.casefold()
        if observed_user is not None and not same_user:
            try:
                expected_sid = account_sid(user)
                same_user = (observed_user == expected_sid
                             or account_sid(observed_user) == expected_sid)
            except (Blocked, OSError, AttributeError, ValueError):
                return False
        return (same_user
                and get("t:Principals/t:Principal/t:LogonType") == "S4U"
                and get("t:Principals/t:Principal/t:RunLevel") == "LeastPrivilege"
                and get("t:Triggers/t:BootTrigger/t:Enabled") == "true"
                and get("t:Settings/t:Enabled") == "true"
                and get("t:Actions/t:Exec/t:Command") == str(python)
                and get("t:Actions/t:Exec/t:Arguments") == f'-B "{runner}"'
                and get("t:Actions/t:Exec/t:WorkingDirectory") == str(runner.parent))
    except ET.ParseError:
        return False


def schtasks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks.exe", *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=30, check=False)


def build_task_definition(service, python: Path, runner: Path, user: str):
    definition = service.NewTask(0)
    definition.RegistrationInfo.Description = "Noteri Worker Pool API native loopback"
    settings = definition.Settings
    settings.Enabled = True
    settings.StartWhenAvailable = True
    settings.DisallowStartIfOnBatteries = False
    settings.StopIfGoingOnBatteries = False
    settings.MultipleInstances = 2
    settings.ExecutionTimeLimit = "PT0S"
    trigger = definition.Triggers.Create(8)
    trigger.Enabled = True
    trigger.Delay = "PT20S"
    action = definition.Actions.Create(0)
    action.Path = str(python)
    action.Arguments = f'-B "{runner}"'
    action.WorkingDirectory = str(runner.parent)
    principal = definition.Principal
    principal.UserId = user
    principal.LogonType = 2
    principal.RunLevel = 0
    return definition


def register_task_com(python: Path, runner: Path, user: str, package: Path) -> subprocess.CompletedProcess:
    """Register S4U with the same Task Scheduler COM route used by Noteri's host agent."""
    try:
        site.addsitedir(str(package))
        import win32com.client  # type: ignore
        service = win32com.client.Dispatch("Schedule.Service")
        service.Connect()
        folder = service.GetFolder(r"\Automation")
        principal_sid = account_sid(user)
        definition = build_task_definition(service, python, runner, principal_sid)
        folder.RegisterTaskDefinition("NoteriWorkerPoolApi", definition, 2,
                                      principal_sid, None, 2)
        return subprocess.CompletedProcess(["RegisterTaskDefinition"], 0, stdout=b"", stderr=b"")
    except Exception as exc:
        return subprocess.CompletedProcess(["RegisterTaskDefinition"], 1, stdout=b"",
                                           stderr=str(exc).encode("utf-8", errors="replace"))


def registration_diagnostic(root: Path, completed: subprocess.CompletedProcess) -> str | None:
    """Keep the bounded native error privately; return only a random locator."""
    identifier = uuid.uuid4().hex
    path = root / f"registration-failure-{identifier}.json"
    payload = {"returncode": completed.returncode,
               "stdout": (completed.stdout or b"")[:4096].decode("utf-8", errors="replace"),
               "stderr": (completed.stderr or b"")[:4096].decode("utf-8", errors="replace")}
    try:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False)
    except OSError:
        return None
    return identifier


def http_status(path: str, bearer: str | None = None) -> tuple[int, dict | None]:
    headers = {} if bearer is None else {"Authorization": "Bearer " + bearer}
    try:
        with urllib.request.urlopen(urllib.request.Request(
                "http://127.0.0.1:8097" + path, headers=headers), timeout=3) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, None


def listener_owned_by_task(python: Path, runner: Path) -> bool:
    try:
        import psutil
        listeners = [item for item in psutil.net_connections(kind="tcp")
                     if item.status == psutil.CONN_LISTEN and item.laddr
                     and item.laddr.ip == "127.0.0.1" and item.laddr.port == 8097]
        if len(listeners) != 1 or listeners[0].pid is None:
            return False
        parent = psutil.Process(listeners[0].pid).parent()
        if parent is None:
            return False
        command = parent.cmdline()
        return (len(command) == 3 and command[1] == "-B"
                and Path(command[0]).resolve() == python.resolve()
                and Path(command[2]).resolve() == runner.resolve())
    except (ImportError, OSError, ValueError):
        return False
    except Exception:
        return False


def verify_api(token_file: Path, python: Path, runner: Path) -> bool:
    if not listener_owned_by_task(python, runner):
        return False
    status, health = http_status("/health")
    if (status != 200 or not isinstance(health, dict)
            or health.get("status") != "healthy"
            or health.get("auth_configured") is not True
            or health.get("expected_rules_sha_configured") is not True
            or health.get("contract_version") != "v1"):
        return False
    negative, _ = http_status("/v1/contract", "invalid-activation-control")
    if not listener_owned_by_task(python, runner):
        return False
    token = token_file.read_text(encoding="utf-8").strip()
    positive, descriptor = http_status("/v1/contract", token)
    return (negative == 401 and positive == 200 and isinstance(descriptor, dict)
            and descriptor.get("contract_name") == "engineering-worker-pool"
            and descriptor.get("contract_version") == "v1"
            and listener_owned_by_task(python, runner))


def qualify_common(local: Path, source: Path) -> tuple[Path, Path, Path]:
    if os.name != "nt" or socket.gethostname().casefold() != "noteri":
        raise Blocked("host")
    profile = json.loads((local / reference.PROFILE_RELATIVE).read_text(encoding="utf-8"))
    if profile.get("profile") != "NORMAL":
        raise Blocked("profile")
    root, release, venv_root = venv._paths(local)
    requirements_hash = venv._check_release(release)
    if not venv._verify(venv_root, requirements_hash,
                        venv.preflight.required_packages(release / "requirements.txt")):
        raise Blocked("venv")
    if reference.qualify(localappdata=local, hostname="Noteri", profile="NORMAL",
                         platform="nt")["result"] != "REFERENCE_PRIVATE_UNREAD":
        raise Blocked("credential")
    if not control.verify(root / "control" / control.TARGET_NAME):
        raise Blocked("control_package")
    for name in RUNNER_FILES:
        if not (source / name).is_file():
            raise Blocked("runner_source")
    try:
        import psutil  # noqa: F401 - required for independent listener attribution.
    except ImportError as exc:
        raise Blocked("process_inventory_unavailable") from exc
    return root, venv_root, local / reference.TOKEN_RELATIVE


def qualify(local: Path, source: Path) -> tuple[Path, Path, Path]:
    root, venv_root, token = qualify_common(local, source)
    if not task_absent(Path(os.environ.get("WINDIR", "C:\\Windows"))):
        raise Blocked("task_not_absent")
    if not listener_absent():
        raise Blocked("listener_not_absent")
    if (root / "bin").exists():
        raise Blocked("bin_already_present")
    if (root / "data").exists():
        raise Blocked("data_already_present")
    return root, venv_root, token


def existing_task(local: Path, source: Path) -> tuple[Path, Path, Path, Path] | None:
    root, venv_root, token = qualify_common(local, source)
    bin_dir = root / "bin"
    stage.ensure_no_link_components(bin_dir)
    for name in RUNNER_FILES:
        candidate = bin_dir / name
        if not candidate.is_file() or sha256(candidate) != sha256(source / name):
            return None
    python = venv._python(venv_root)
    runner = bin_dir / RUNNER_FILES[0]
    user = f"{socket.gethostname()}\\{getpass.getuser()}"
    queried = schtasks("/Query", "/TN", TASK_NAME, "/XML")
    if queried.returncode != 0 or not task_matches(queried.stdout, python, runner, user):
        return None
    return root, token, python, runner


def wait_api(token_file: Path, python: Path, runner: Path, seconds: float = 30) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if verify_api(token_file, python, runner):
                return True
        except (OSError, TimeoutError, ValueError):
            pass
        time.sleep(0.5)
    return False


def activate(local: Path, source: Path) -> dict:
    if not is_admin():
        raise Blocked("elevation_required")
    root, venv_root, token_file = qualify(local, source)
    bin_dir = root / "bin"
    python = venv._python(venv_root)
    runner = bin_dir / RUNNER_FILES[0]
    user = f"{socket.gethostname()}\\{getpass.getuser()}"
    registered = False
    created_bin = False
    created_data = False
    diagnostic_id = None
    phase = "materialize"
    try:
        bin_dir.mkdir(exist_ok=False)
        created_bin = True
        (root / "data").mkdir(exist_ok=False)
        created_data = True
        for name in RUNNER_FILES:
            shutil.copyfile(source / name, bin_dir / name)
            if sha256(source / name) != sha256(bin_dir / name):
                raise Blocked("runner_copy")
        xml_path = bin_dir / "registration.xml"
        xml_path.write_bytes(task_xml(python, runner, user))
        phase = "register"
        created = register_task_com(python, runner, user,
                                    root / "control" / control.TARGET_NAME)
        if created.returncode != 0:
            diagnostic_id = registration_diagnostic(root, created)
            queried = schtasks("/Query", "/TN", TASK_NAME, "/XML")
            if queried.returncode == 0:
                if not task_matches(queried.stdout, python, runner, user):
                    return {"result": "BLOCKED_REGISTRATION_AMBIGUOUS", "phase": phase,
                            "activated": False, "state_changed": True,
                            "diagnostic_id": diagnostic_id}
                registered = True
            elif not task_absent(Path(os.environ.get("WINDIR", "C:\\Windows"))):
                return {"result": "BLOCKED_REGISTRATION_AMBIGUOUS", "phase": phase,
                        "activated": False, "state_changed": True,
                        "diagnostic_id": diagnostic_id}
            raise Blocked("register")
        registered = True
        xml_path.unlink()
        phase = "task_readback"
        queried = schtasks("/Query", "/TN", TASK_NAME, "/XML")
        if queried.returncode != 0 or not task_matches(queried.stdout, python, runner, user):
            raise Blocked("task_readback")
        phase = "start"
        if schtasks("/Run", "/TN", TASK_NAME).returncode != 0:
            raise Blocked("start")
        phase = "api_readback"
        if wait_api(token_file, python, runner):
            return {"result": "API_ACTIVATED", "activated": True,
                    "task_s4u_verified": True, "contract_v1_verified": True,
                    "negative_auth_verified": True, "state_changed": True}
        raise Blocked("api_readback")
    except Exception:
        if registered:
            schtasks("/End", "/TN", TASK_NAME)
            deleted = schtasks("/Delete", "/TN", TASK_NAME, "/F")
            if deleted.returncode != 0 or not task_absent(
                    Path(os.environ.get("WINDIR", "C:\\Windows"))):
                return {"result": "BLOCKED_ROLLBACK", "phase": phase,
                        "activated": False, "state_changed": True}
            for _ in range(20):
                if listener_absent():
                    break
                time.sleep(0.5)
            if not listener_absent():
                return {"result": "BLOCKED_ROLLBACK", "phase": phase,
                        "activated": False, "state_changed": True}
        try:
            data_dir = root / "data"
            if created_data and data_dir.exists():
                stage.ensure_no_link_components(data_dir)
                shutil.rmtree(data_dir)
            if created_bin and bin_dir.is_dir():
                for name in (*RUNNER_FILES, "registration.xml"):
                    (bin_dir / name).unlink(missing_ok=True)
                bin_dir.rmdir()
        except OSError:
            return {"result": "BLOCKED_ROLLBACK", "phase": phase, "activated": False}
        return {"result": "BLOCKED_ACTIVATION_ROLLED_BACK", "phase": phase,
                "activated": False, "state_changed": False,
                "diagnostic_id": diagnostic_id}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "activate", "status", "restore"),
                        default="plan")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    base = {"schema_version": "1", "source_sha": reference.SOURCE_SHA,
            "activated": False, "state_changed": False}
    try:
        local = Path(os.environ["LOCALAPPDATA"])
        source = Path(__file__).resolve().parent
        if args.mode == "status":
            existing = existing_task(local, source)
            ready = existing is not None and verify_api(*existing[1:])
            payload = {**base, "result": "API_ACTIVE" if ready else "BLOCKED_EXISTING",
                       "activated": ready}
        elif args.mode == "plan":
            if task_absent(Path(os.environ.get("WINDIR", "C:\\Windows"))):
                qualify(local, source)
                payload = {**base, "result": "ACTIVATION_PLAN_READY"}
            else:
                existing = existing_task(local, source)
                ready = existing is not None and verify_api(*existing[1:])
                payload = {**base, "result": "ALREADY_ACTIVE" if ready else "BLOCKED_EXISTING",
                           "activated": ready}
        elif args.confirm != CONFIRM:
            payload = {**base, "result": "BLOCKED_ACTION"}
        elif args.mode == "restore":
            existing = existing_task(local, source)
            if existing is None or not listener_absent():
                payload = {**base, "result": "BLOCKED_EXISTING"}
            elif (schtasks("/Run", "/TN", TASK_NAME).returncode == 0
                  and wait_api(*existing[1:])):
                payload = {**base, "result": "API_RESTORED", "activated": True,
                           "state_changed": True}
            else:
                payload = {**base, "result": "BLOCKED_RESTORE"}
        else:
            if task_absent(Path(os.environ.get("WINDIR", "C:\\Windows"))):
                payload = {**base, **activate(local, source)}
            else:
                existing = existing_task(local, source)
                ready = existing is not None and verify_api(*existing[1:])
                payload = {**base, "result": "ALREADY_ACTIVE" if ready else "BLOCKED_EXISTING",
                           "activated": ready}
    except Blocked as exc:
        payload = {**base, "result": ("BLOCKED_ELEVATION_REQUIRED"
                                     if str(exc) == "elevation_required"
                                     else "BLOCKED_PRECONDITION")}
    except Exception:
        payload = {**base, "result": "BLOCKED_PRECONDITION"}
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["result"] in {"ACTIVATION_PLAN_READY", "API_ACTIVATED",
                                       "API_ACTIVE", "ALREADY_ACTIVE", "API_RESTORED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
