"""Risk-1 Noteri PostgreSQL 18 inventory. Never connects or mutates the DB."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys

ROOT = Path("C:/Program Files/PostgreSQL/18")
REPO = "ericson-j-santos/noteri-runtime"
BRANCH = "feat/noteri-pg18-service-observation-20261025"
SHA = re.compile(r"[0-9a-f]{40}\Z")
STATES = {1:"stopped",2:"starting",3:"stopping",4:"running",
          5:"resuming",6:"pausing",7:"paused"}

class Blocked(RuntimeError):
    pass

def require(ok, code):
    if not ok: raise Blocked(code)

def provenance(env, host, platform, now=None):
    now=now or datetime.now(timezone.utc)
    try:
        start=datetime.fromisoformat(
            env.get("NOTERI_PG_ADMITTED_AT","").replace("Z","+00:00"))
        age=(now-start).total_seconds()
    except (ValueError,TypeError):
        raise Blocked("admission_unverified") from None
    sha=env.get("EXPECTED_SOURCE_SHA","")
    rule=env.get("RULES_SHA","")
    run=env.get("GITHUB_RUN_ID","")
    require(platform=="win32" and host.casefold()=="noteri" and
        env.get("COMPUTERNAME","").casefold()=="noteri" and
        env.get("GITHUB_ACTIONS")=="true" and
        env.get("GITHUB_REPOSITORY")==REPO and
        env.get("GITHUB_EVENT_NAME")=="pull_request" and
        env.get("GITHUB_HEAD_REF")==BRANCH and
        env.get("GITHUB_ACTOR")=="ericson-j-santos" and
        env.get("RUNNER_NAME","").casefold().startswith("noteri") and
        env.get("RUNNER_OS")=="Windows" and
        env.get("RUNNER_ARCH")=="X64" and
        env.get("GITHUB_RUN_ATTEMPT")=="1" and
        env.get("SESSION_LAUNCH_RESULT")=="SESSION_LAUNCH_OK" and
        env.get("SESSION_STATE_VALIDATED")=="true" and
        SHA.fullmatch(sha) and SHA.fullmatch(rule) and
        re.fullmatch(r"[1-9][0-9]{0,19}",run) and
        start.tzinfo is not None and 0<=age<=300,
        "identity_or_session_blocked")
    target=Path(env.get("SESSION_TARGET_PATH") or "Z:/none")
    require(target.is_absolute() and target.resolve()==Path.cwd().resolve(),
            "session_target_blocked")
    return {"source_sha":sha,"rules_sha":rule,"run_id":run,
            "correlation_id":"noteri-pg-"+run+"-1"}

def fixed_exists(path, is_directory=False):
    try:
        if path.is_symlink() or getattr(path,"is_junction",lambda:False)():
            return False
        st=path.lstat()
        return stat.S_ISDIR(st.st_mode) if is_directory else stat.S_ISREG(st.st_mode)
    except OSError:
        return False

def service_state():
    if os.name!="nt": return "unverified"
    api=ctypes.WinDLL("Advapi32",use_last_error=True)
    open_mgr=api.OpenSCManagerW
    open_mgr.argtypes=(wintypes.LPCWSTR,wintypes.LPCWSTR,wintypes.DWORD)
    open_mgr.restype=wintypes.HANDLE
    open_svc=api.OpenServiceW
    open_svc.argtypes=(wintypes.HANDLE,wintypes.LPCWSTR,wintypes.DWORD)
    open_svc.restype=wintypes.HANDLE
    query=api.QueryServiceStatusEx
    query.argtypes=(wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,
                    wintypes.DWORD,ctypes.POINTER(wintypes.DWORD))
    query.restype=wintypes.BOOL
    close=api.CloseServiceHandle
    close.argtypes=(wintypes.HANDLE,)
    close.restype=wintypes.BOOL
    mgr=open_mgr(None,None,1)
    if not mgr: return "unverified"
    svc=None
    try:
        svc=open_svc(mgr,"postgresql-x64-18",4)
        if not svc: return "not_registered" if ctypes.get_last_error()==1060 else "unverified"
        data=(wintypes.DWORD*9)()
        length=wintypes.DWORD(0)
        if not query(svc,0,ctypes.byref(data),ctypes.sizeof(data),
                     ctypes.byref(length)): return "unverified"
        return STATES.get(data[1],"unknown")
    finally:
        if svc: close(svc)
        close(mgr)

def inspect():
    data=ROOT/"data"
    version="unverified"
    if fixed_exists(data/"PG_VERSION"):
        try: version=(data/"PG_VERSION").read_text("ascii").strip()
        except (OSError,UnicodeError): raise Blocked("version_unreadable") from None
        require(version=="18","version_unexpected")
    return {"pg_version":version,
            "install_present":fixed_exists(ROOT,True),
            "binaries_present":all(fixed_exists(ROOT/"bin"/name)
                for name in ("postgres.exe","psql.exe","pg_ctl.exe")),
            "data_directory_present":fixed_exists(data,True),
            "postmaster_marker_present":fixed_exists(data/"postmaster.pid"),
            "service_state":service_state()}

def collect(env, host, platform, probe=inspect, now=None):
    provenance_data=provenance(env,host,platform,now)
    data=probe()
    require(type(data) is dict and set(data)=={
        "pg_version","install_present","binaries_present",
        "data_directory_present","postmaster_marker_present","service_state"} and
        data["pg_version"] in ("18","unverified") and
        data["service_state"] in set(STATES.values())|{"unverified","unknown","not_registered"} and
        all(type(data[k]) is bool for k in (
            "install_present","binaries_present","data_directory_present",
            "postmaster_marker_present")),"schema_invalid")
    return {"result":"NOTERI_PG18_NATIVE_READONLY",
            **provenance_data,"postgres":data,
            "native_binary_installed":data["pg_version"]=="18" and
                data["install_present"] and data["binaries_present"],
            "db_connected":False,"tls_verified":False,
            "shared_authority_verified":False,"backup_verified":False,
            "configuration_changed":False,"service_changed":False,
            "credentials_read":False,"packages_installed":False,
            "docker_used":False,"external_db_used":False,"ready_for_pr":False}

def main():
    try:
        require(len(sys.argv)==1,"arguments_invalid")
        value=collect(dict(os.environ),socket.gethostname(),sys.platform)
        result=json.dumps(value,sort_keys=True,separators=(",",":"))
        require(len(result)<=2000,"receipt_too_large")
        print(result)
        return 0
    except (Blocked,ValueError,TypeError,OSError):
        print(json.dumps({"result":"NOTERI_PG18_READONLY_BLOCKED",
                          "ready_for_pr":False},sort_keys=True))
        return 2

if __name__=="__main__":raise SystemExit(main())
