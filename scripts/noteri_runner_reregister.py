#!/usr/bin/env python3
"""Bootstrap fail-closed para re-registro do GitHub Actions Runner no Noteri.

A inspeção local não registra, inicia ou reconfigura o runner. O marcador local
não comprova conectividade ou pickup no GitHub. O caminho legado de registro
continua separado; sua execução não foi homologada por este incremento.
"""
from __future__ import annotations
import argparse,json,os,shutil,socket,subprocess,time,zipfile,sys,getpass,ctypes
import hashlib
import stat
from datetime import datetime,timezone,timedelta
from urllib.parse import urlsplit
from pathlib import Path

EXPECTED_HOST="Noteri"
EXPECTED_REPOSITORY="ericson-j-santos/noteri-runtime"
EXPECTED_URL="https://github.com/ericson-j-santos/noteri-runtime"
EXPECTED_NAME="Noteri-runtime"
EXPECTED_LABELS=("noteri","reqsys-dev","noteri-runtime")
CONFIRM="REREGISTER-NOTERI-RUNNER"
EXPECTED_GITHUB_LOGIN="ericson-j-santos"
RUNNER_VERSION="2.338.0"
RUNNER_PACKAGE_NAME=f"actions-runner-win-x64-{RUNNER_VERSION}.zip"
RUNNER_PACKAGE_SHA256="f48e0750a21812bca5f82de5f7f5aeae71abee647fab5a582f1742d07eba455f"
RUNNER_PACKAGE_SIZE=104063355
CONTROL_SCHEMA="noteri-runtime-runner/v1"
KEEPALIVE_TASK="ReqSys-NoteriRuntimeRunnerKeepalive"
RUN_VALUE_NAME="ReqSysNoteriRuntimeRunnerKeepalive"
RUN_KEY=r"Software\Microsoft\Windows\CurrentVersion\Run"
TASK_TRIGGER_BOOT=8
TASK_TRIGGER_DAILY=2
TASK_ACTION_EXEC=0
TASK_LOGON_S4U=2
TASK_RUNLEVEL_LUA=0
TASK_CREATE_OR_UPDATE=6
TASK_INSTANCES_IGNORE_NEW=2
PROCESS_QUERY_LIMITED_INFORMATION=0x1000

class BootstrapError(RuntimeError): pass

def validate(host,repository,confirm):
    if host.casefold()!=EXPECTED_HOST.casefold(): raise BootstrapError("host invalido")
    if repository!=EXPECTED_REPOSITORY: raise BootstrapError("repositorio invalido")
    if confirm!=CONFIRM: raise BootstrapError("confirmacao invalida")

MARKER_LIMIT = 64 * 1024
IDENTITY_ERRORS = (
    "runner_path_reparse", "runner_marker_invalid", "runner_marker_changed",
    "runner_repository_mismatch", "runner_agent_mismatch", "runner_workfolder_mismatch",
    "runner_configuration_exists", "runner_marker_missing", "watchdog_metadata_invalid",
)


def _regular_path(path: Path) -> None:
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BootstrapError("runner_path_reparse")


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BootstrapError("runner_marker_invalid")
        value[key] = item
    return value


def _read_object(path: Path):
    _regular_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MARKER_LIMIT:
        raise BootstrapError("runner_marker_invalid")
    with path.open("rb") as handle:
        if _signature(os.fstat(handle.fileno())) != _signature(before):
            raise BootstrapError("runner_marker_changed")
        raw = handle.read(MARKER_LIMIT + 1)
        after = os.fstat(handle.fileno())
    if (len(raw) != before.st_size or _signature(after) != _signature(before)
            or _signature(path.stat()) != _signature(before)):
        raise BootstrapError("runner_marker_changed")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise BootstrapError("runner_marker_invalid") from None
    if not isinstance(value, dict):
        raise BootstrapError("runner_marker_invalid")
    return value, hashlib.sha256(raw).hexdigest()


def validate_home(root: Path) -> Path:
    # Check before resolve(), which would hide a junction/symlink in the input.
    root = root.absolute()
    _regular_path(root)
    for item in (root / "config.cmd", root / "run.cmd", root / "bin" / "Runner.Listener.exe"):
        _regular_path(item)
        if not item.is_file():
            raise BootstrapError("runner_home incompleto")
    return root.resolve()


def local_root() -> Path:
    local=os.environ.get("LOCALAPPDATA")
    if not local: raise BootstrapError("localappdata_missing")
    return Path(local)/"ReqSys"

def runner_package_path() -> Path:
    return local_root()/RUNNER_PACKAGE_NAME

def dedicated_home() -> Path:
    return local_root()/"NoteriRuntimeRunner"

def control_root() -> Path:
    return local_root()/"NoteriRuntimeRunnerControl"

def _sha256_file(path:Path)->str:
    digest=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda:handle.read(1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()

def verify_package(path:Path)->dict:
    _regular_path(path)
    info=path.stat()
    if not stat.S_ISREG(info.st_mode): raise BootstrapError("runner_package_not_regular")
    if info.st_size!=RUNNER_PACKAGE_SIZE: raise BootstrapError("runner_package_size_mismatch")
    digest=_sha256_file(path)
    if digest!=RUNNER_PACKAGE_SHA256: raise BootstrapError("runner_package_hash_mismatch")
    return {"version":RUNNER_VERSION,"sha256":digest,"size":info.st_size}

def _safe_member(name:str)->Path:
    normalized=name.replace("\\","/")
    value=Path(normalized)
    if not normalized or normalized.startswith("/") or ":" in value.parts[0] or any(part in ("","..") for part in value.parts):
        raise BootstrapError("runner_archive_path_invalid")
    return value

def extract_package(package:Path,destination:Path)->None:
    if destination.exists(): raise BootstrapError("runner_destination_exists")
    staging=destination.with_name(destination.name+".stage")
    if staging.exists(): raise BootstrapError("runner_staging_exists")
    staging.mkdir(parents=True)
    try:
        with zipfile.ZipFile(package,"r") as archive:
            for info in archive.infolist():
                relative=_safe_member(info.filename)
                unix_mode=(info.external_attr>>16)&0xFFFF
                if stat.S_ISLNK(unix_mode): raise BootstrapError("runner_archive_link_rejected")
                target=staging.joinpath(*relative.parts)
                if info.is_dir():
                    target.mkdir(parents=True,exist_ok=True);continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with archive.open(info,"r") as source,target.open("wb") as output:
                    shutil.copyfileobj(source,output,1024*1024)
        validate_home(staging)
        os.replace(staging,destination)
    except Exception:
        if staging.exists(): shutil.rmtree(staging,ignore_errors=True)
        raise

def verify_extracted_files(package:Path,root:Path)->None:
    required=("config.cmd","run.cmd","bin/Runner.Listener.exe")
    with zipfile.ZipFile(package,"r") as archive:
        names=set(archive.namelist())
        for name in required:
            if name not in names: raise BootstrapError("runner_package_contract_missing")
            expected=hashlib.sha256(archive.read(name)).hexdigest()
            target=root.joinpath(*name.split("/"))
            if not target.is_file() or _sha256_file(target)!=expected:
                raise BootstrapError("runner_extracted_hash_mismatch")

def verify_package_receipt(root:Path,package_info:dict)->None:
    receipt=root/"package-receipt.json"
    if not receipt.is_file(): raise BootstrapError("runner_package_receipt_missing")
    try: value=json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError,ValueError): raise BootstrapError("runner_package_receipt_invalid") from None
    expected={"schema_version":"1",**package_info}
    if value!=expected: raise BootstrapError("runner_package_receipt_invalid")

def runner_version(root:Path)->str:
    listener=root/"bin"/"Runner.Listener.exe"
    cp=subprocess.run([str(listener),"--version"],cwd=str(root),capture_output=True,text=True,
        encoding="utf-8",errors="replace",timeout=30,check=False)
    version=cp.stdout.strip().splitlines()[-1] if cp.returncode==0 and cp.stdout.strip() else ""
    if version!=RUNNER_VERSION: raise BootstrapError("runner_version_mismatch")
    return version

def _atomic_json(path:Path,payload:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(payload,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(tmp,path)

def prepare_dedicated_home()->tuple[Path,bool]:
    package=runner_package_path()
    package_info=verify_package(package)
    root=dedicated_home()
    if root.exists():
        validate_home(root);runner_version(root);verify_extracted_files(package,root)
        verify_package_receipt(root,package_info)
        return root,False
    extract_package(package,root)
    runner_version(root);verify_extracted_files(package,root)
    _atomic_json(root/"package-receipt.json",{"schema_version":"1",**package_info})
    verify_package_receipt(root,package_info)
    return root,True

def write_control_metadata(root:Path,*,source_sha:str,correlation_id:str,idempotency_key:str)->dict:
    if not isinstance(source_sha,str) or len(source_sha)!=40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise BootstrapError("source_sha_invalid")
    for value,code in ((correlation_id,"correlation_id_invalid"),(idempotency_key,"idempotency_key_invalid")):
        if not isinstance(value,str) or not 8<=len(value)<=128 or any(not(c.isalnum() or c in "_.:-") for c in value):
            raise BootstrapError(code)
    identity=local_identity(root)
    if identity is None: raise BootstrapError("runner_marker_missing")
    previous=read_control_metadata()
    payload={"schema_version":CONTROL_SCHEMA,"enabled":True,"host":EXPECTED_HOST,
        "repository":EXPECTED_REPOSITORY,"runner_name":EXPECTED_NAME,"runner_home":str(root),
        "labels":list(EXPECTED_LABELS),"source_sha":source_sha,"correlation_id":correlation_id,
        "idempotency_key":idempotency_key,"package_sha256":RUNNER_PACKAGE_SHA256,
        "runner_version":RUNNER_VERSION,"identity":identity,
        "runner_pid":previous.get("runner_pid"),"restarts":int(previous.get("restarts") or 0)}
    _atomic_json(control_root()/"metadata.json",payload)
    return payload

def _utc_now()->str:
    return datetime.now(timezone.utc).isoformat()

def _process_image(pid:int)->str|None:
    if os.name!="nt" or type(pid) is not int or pid<=0: return None
    kernel32=ctypes.windll.kernel32
    handle=kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,False,pid)
    if not handle: return None
    try:
        size=ctypes.c_ulong(32768);buf=ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)): return None
        return buf.value
    finally:
        kernel32.CloseHandle(handle)

def process_matches(pid:int,listener:Path)->bool:
    observed=_process_image(pid)
    if not observed: return False
    try: return Path(observed).resolve()==listener.resolve()
    except OSError: return False

def read_control_metadata()->dict:
    path=control_root()/"metadata.json"
    if not path.is_file(): return {}
    try: value=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,ValueError): return {}
    return value if isinstance(value,dict) else {}

def update_listener_metadata(pid:int,restarts:int)->dict:
    metadata=read_control_metadata()
    if metadata.get("schema_version")!=CONTROL_SCHEMA: raise BootstrapError("control_metadata_invalid")
    metadata.update({"runner_pid":pid,"restarts":restarts,"runner_last_started_at":_utc_now()})
    _atomic_json(control_root()/"metadata.json",metadata)
    return metadata

def ensure_listener(root:Path)->dict:
    identity=local_identity(root)
    if identity is None: raise BootstrapError("runner_marker_missing")
    metadata=read_control_metadata()
    prior_pid=metadata.get("runner_pid")
    restarts=int(metadata.get("restarts") or 0)
    listener=root/"bin"/"Runner.Listener.exe"
    if type(prior_pid) is int and process_matches(prior_pid,listener):
        return {"runner_pid":prior_pid,"reused":True,"restarts":restarts}
    pid=start(root);restarts+=1;update_listener_metadata(pid,restarts)
    return {"runner_pid":pid,"reused":False,"restarts":restarts}

def _scheduler():
    try: import win32com.client
    except ImportError as exc: raise BootstrapError("pywin32_missing") from exc
    service=win32com.client.Dispatch("Schedule.Service");service.Connect();return service

def _current_user_id()->str:
    computer=socket.gethostname().strip();user=getpass.getuser().strip()
    if not computer or not user: raise BootstrapError("windows_identity_missing")
    return f"{computer}\\{user}"

def _stable_script()->Path:
    target=control_root()/"runtime";target.mkdir(parents=True,exist_ok=True)
    source=Path(__file__).resolve();destination=target/"noteri_runner_reregister.py"
    shutil.copy2(source,destination)
    if _sha256_file(source)!=_sha256_file(destination): raise BootstrapError("stable_script_hash_mismatch")
    return destination

def _keepalive_command(script:Path)->str:
    return subprocess.list2cmdline([str(script),"--keepalive-dedicated","--confirm",CONFIRM])

def install_run_key(script:Path)->dict:
    if os.name!="nt": raise BootstrapError("windows_required")
    import winreg
    command=f'"{sys.executable}" {_keepalive_command(script)}'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,RUN_KEY,0,winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key,RUN_VALUE_NAME,0,winreg.REG_SZ,command)
    return {"mode":"hkcu_run","requires_user_logon":True}

def install_keepalive()->dict:
    script=_stable_script()
    try:
        service=_scheduler();root=service.GetFolder("\\");definition=service.NewTask(0)
        definition.RegistrationInfo.Description="noteri-runtime GitHub runner keepalive"
        definition.Settings.Enabled=True;definition.Settings.StartWhenAvailable=True
        definition.Settings.DisallowStartIfOnBatteries=False;definition.Settings.StopIfGoingOnBatteries=False
        definition.Settings.MultipleInstances=TASK_INSTANCES_IGNORE_NEW;definition.Settings.ExecutionTimeLimit="PT2M"
        boot=definition.Triggers.Create(TASK_TRIGGER_BOOT);boot.Enabled=True;boot.Delay="PT20S"
        daily=definition.Triggers.Create(TASK_TRIGGER_DAILY);daily.Enabled=True
        daily.StartBoundary=(datetime.now().astimezone()+timedelta(seconds=30)).replace(microsecond=0).isoformat()
        daily.DaysInterval=1;daily.Repetition.Interval="PT5M";daily.Repetition.Duration="P1D"
        daily.Repetition.StopAtDurationEnd=False
        action=definition.Actions.Create(TASK_ACTION_EXEC);action.Path=sys.executable
        action.Arguments=_keepalive_command(script);action.WorkingDirectory=str(script.parent)
        principal=definition.Principal;principal.UserId=_current_user_id()
        principal.LogonType=TASK_LOGON_S4U;principal.RunLevel=TASK_RUNLEVEL_LUA
        root.RegisterTaskDefinition(KEEPALIVE_TASK,definition,TASK_CREATE_OR_UPDATE,
            principal.UserId,"",TASK_LOGON_S4U)
        task=root.GetTask(KEEPALIVE_TASK)
        return {"mode":"task_s4u_limited","requires_user_logon":False,"task":KEEPALIVE_TASK,
            "enabled":bool(task.Enabled),"run_level":"limited"}
    except Exception as exc:
        text=repr(exc).casefold()
        if "access" in text or "-2147024891" in text or "acesso negado" in text or isinstance(exc,ImportError):
            return install_run_key(script)
        if isinstance(exc,BootstrapError) and str(exc)=="pywin32_missing": return install_run_key(script)
        raise

def local_identity(root: Path) -> dict | None:
    """Only .runner metadata is opened; no credentials or logs are read."""
    marker = root / ".runner"
    _regular_path(marker)
    try:
        marker.lstat()
    except FileNotFoundError:
        return None
    value, marker_sha256 = _read_object(marker)
    url = value.get("gitHubUrl")
    if not isinstance(url, str):
        raise BootstrapError("runner_repository_mismatch")
    try:
        parsed = urlsplit(url)
        valid_url = (parsed.scheme == "https" and parsed.netloc.casefold() == "github.com"
                     and not parsed.query and not parsed.fragment
                     and parsed.path.rstrip("/").casefold() == "/" + EXPECTED_REPOSITORY.casefold()
                     and url == url.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in url))
    except ValueError:
        valid_url = False
    if not valid_url:
        raise BootstrapError("runner_repository_mismatch")
    if (type(value.get("agentId")) is not int or value["agentId"] <= 0
            or value.get("agentName") != EXPECTED_NAME):
        raise BootstrapError("runner_agent_mismatch")
    if value.get("workFolder") != "_work":
        raise BootstrapError("runner_workfolder_mismatch")
    return {"agent_id": value["agentId"], "agent_name": EXPECTED_NAME,
            "repository": EXPECTED_REPOSITORY, "marker_sha256": marker_sha256}


def configured(root: Path) -> bool:
    return local_identity(root) is not None


def installed_home() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise BootstrapError("watchdog_metadata_invalid")
    metadata = Path(local) / "ReqSys" / "NoteriControlPlaneWatchdog" / "metadata.json"
    value, _ = _read_object(metadata)
    if (value.get("host") != EXPECTED_HOST
            or value.get("service") != "reqsys-noteri-control-plane-watchdog"
            or not isinstance(value.get("runner_home"), str)):
        raise BootstrapError("watchdog_metadata_invalid")
    root = Path(value["runner_home"])
    if not root.is_absolute():
        raise BootstrapError("watchdog_metadata_invalid")
    return validate_home(root)


def gh_env():
    env = dict(os.environ)
    for key in list(env):
        if key.upper() in {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                           "GITHUB_ENTERPRISE_TOKEN", "GH_CONFIG_DIR", "GH_DEBUG"} or key.upper().startswith("ACTIONS_RUNNER_INPUT_"):
            env.pop(key, None)
    env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", GIT_TERMINAL_PROMPT="0")
    return env

def find_gh()->Path:
    found=shutil.which("gh")
    candidates=[Path(found) if found else None,
        Path(os.environ.get("ProgramFiles") or r"C:\\Program Files")/"GitHub CLI"/"gh.exe",
        Path(os.environ.get("LOCALAPPDATA") or "")/"Programs"/"GitHub CLI"/"gh.exe"]
    for item in candidates:
        if item and item.is_file(): return item
    raise BootstrapError("github_cli_missing")

def registration_token(gh:Path)->str:
    who=subprocess.run([str(gh),"api","user","--jq",".login"],capture_output=True,text=True,
        encoding="utf-8",errors="replace",timeout=30,check=False,env=gh_env())
    if who.returncode!=0 or who.stdout.strip().casefold()!=EXPECTED_GITHUB_LOGIN.casefold():
        raise BootstrapError("github_identity_mismatch")
    cp=subprocess.run([str(gh),"api","--method","POST",
        f"repos/{EXPECTED_REPOSITORY}/actions/runners/registration-token","--jq",".token"],
        capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30,
        check=False,env=gh_env())
    token=cp.stdout.strip()
    if cp.returncode!=0 or len(token)<20: raise BootstrapError("runner_admin_permission_required")
    return token

def diag_snapshot(root:Path)->dict[str,int]:
    diag=root/"_diag"
    if not diag.is_dir(): return {}
    out={}
    for p in diag.glob("Runner_*.log"):
        try: out[str(p.resolve())]=p.stat().st_mtime_ns
        except OSError: pass
    return out

def classify_current_diag(root:Path,before:dict[str,int])->str:
    diag=root/"_diag"
    candidates=[]
    if diag.is_dir():
        for p in diag.glob("Runner_*.log"):
            try:
                key=str(p.resolve()); stamp=p.stat().st_mtime_ns
                if key not in before or stamp>before[key]: candidates.append((stamp,p))
            except OSError: pass
    if not candidates: return "diag_unavailable"
    path=max(candidates,key=lambda item:item[0])[1]
    try: text=path.read_text(encoding="utf-8",errors="replace").casefold()
    except OSError: return "diag_unavailable"
    if "401" in text or "bad credentials" in text: return "http_401"
    if "403" in text or "forbidden" in text: return "http_403"
    if "404" in text or "not found" in text: return "http_404"
    if "already configured" in text: return "already_configured"
    if any(x in text for x in ("timed out","timeout","name or service not known","no such host","connection refused")): return "network"
    return "runner_error"

def configure(root:Path,gh:Path)->None:
    if configured(root):
        raise BootstrapError("runner_configuration_exists")
    before=diag_snapshot(root)
    token=registration_token(gh)
    child_env=gh_env()
    child_env["ACTIONS_RUNNER_INPUT_TOKEN"]=token
    try:
        cmd=[str(root/"bin"/"Runner.Listener.exe"),"configure","--unattended","--url",EXPECTED_URL,
             "--name",EXPECTED_NAME,"--labels",",".join(EXPECTED_LABELS),
             "--work","_work","--disableupdate"]
        r=subprocess.run(cmd,cwd=str(root),env=child_env,capture_output=True,text=True,
                         encoding="utf-8",errors="replace",timeout=120,check=False)
    finally:
        child_env.pop("ACTIONS_RUNNER_INPUT_TOKEN",None)
        token=""
    if r.returncode!=0: raise BootstrapError(f"config_failed:{classify_current_diag(root,before)}")
    if not configured(root): raise BootstrapError("runner_marker_missing")

def start(root:Path)->int:
    try:
        process=subprocess.Popen([str(root/"bin"/"Runner.Listener.exe"),"run"],cwd=str(root),
                         stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.DETACHED_PROCESS,
                         close_fds=True)
    except OSError as exc:
        raise BootstrapError("listener_failed") from exc
    time.sleep(1.0)
    if process.poll() is not None: raise BootstrapError("listener_failed")
    return int(process.pid)

def install_dedicated(*,source_sha:str,correlation_id:str,idempotency_key:str)->dict:
    root,prepared=prepare_dedicated_home()
    identity=local_identity(root)
    registered=False
    listener_pid=None
    if identity is None:
        gh=find_gh();configure(root,gh);registered=True;identity=local_identity(root)
        listener_pid=start(root)
    metadata=write_control_metadata(root,source_sha=source_sha,
        correlation_id=correlation_id,idempotency_key=idempotency_key)
    if listener_pid is not None: metadata=update_listener_metadata(listener_pid,int(metadata.get("restarts") or 0)+1)
    persistence=install_keepalive()
    return {"ok":True,"result":"RUNNER_DEDICATED_INSTALLED","host":EXPECTED_HOST,
            **identity,"prepared_now":prepared,"registered_now":registered,
            "listener_pid":listener_pid,"metadata_written":True,
            "token_persisted":False,"registration_changed":registered,
            "metadata":metadata,"persistence":persistence,
            "actions_qualified":False,"hml_verified":False}

def main()->int:
    p=argparse.ArgumentParser()
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument("--runner-home",type=Path)
    source.add_argument("--inspect-installed",action="store_true")
    source.add_argument("--install-dedicated",action="store_true")
    source.add_argument("--keepalive-dedicated",action="store_true")
    p.add_argument("--inspect-only",action="store_true")
    p.add_argument("--source-sha")
    p.add_argument("--correlation-id")
    p.add_argument("--idempotency-key")
    p.add_argument("--repository",default=EXPECTED_REPOSITORY); p.add_argument("--confirm",required=True)
    a=p.parse_args()
    try:
        validate(socket.gethostname(),a.repository,a.confirm)
        if a.install_dedicated:
            out=install_dedicated(source_sha=a.source_sha or "",
                correlation_id=a.correlation_id or "",idempotency_key=a.idempotency_key or "")
            print(json.dumps(out,sort_keys=True));return 0
        if a.keepalive_dedicated:
            root=dedicated_home();validate_home(root);state=ensure_listener(root)
            out={"ok":True,"result":"RUNNER_KEEPALIVE_OK","host":EXPECTED_HOST,
                 **state,"actions_qualified":False,"hml_verified":False}
            print(json.dumps(out,sort_keys=True));return 0
        root=installed_home() if a.inspect_installed else validate_home(a.runner_home)
        identity=local_identity(root)
        if identity is not None:
            out={"ok":True,"result":"RUNNER_LOCAL_CONFIGURATION_VERIFIED","host":EXPECTED_HOST,
                 **identity,"token_persisted":False}
        elif a.inspect_only or a.inspect_installed:
            raise BootstrapError("runner_marker_missing")
        else:
            gh=find_gh(); configure(root,gh); start(root)
            out={"ok":True,"result":"RUNNER_REREGISTERED","host":EXPECTED_HOST,
                 "repository":EXPECTED_REPOSITORY,"labels":list(EXPECTED_LABELS),"token_persisted":False}
        out.update(actions_qualified=False, hml_verified=False)
        print(json.dumps(out,sort_keys=True)); return 0
    except Exception as e:
        reason=str(e)
        allowed=("github_cli_missing","github_identity_mismatch","runner_admin_permission_required",
                 "runner_home incompleto","config_failed:http_401","config_failed:http_403",
                 "config_failed:http_404","config_failed:already_configured","config_failed:network",
                 "config_failed:diag_unavailable","config_failed:runner_error",
                 "runner_marker_missing","listener_failed",
                 "host invalido","repositorio invalido","confirmacao invalida",
                 "localappdata_missing","runner_package_not_regular","runner_package_size_mismatch",
                 "runner_package_hash_mismatch","runner_archive_path_invalid","runner_archive_link_rejected",
                 "runner_destination_exists","runner_staging_exists","runner_version_mismatch",
                 "runner_package_contract_missing","runner_extracted_hash_mismatch",
                 "runner_package_receipt_missing","runner_package_receipt_invalid",
                 "source_sha_invalid","correlation_id_invalid","idempotency_key_invalid",
                 "control_metadata_invalid","pywin32_missing","windows_identity_missing",
                 "stable_script_hash_mismatch","windows_required")
        allowed += IDENTITY_ERRORS
        state=next((item for item in allowed if reason == item),"bootstrap_failed")
        print(json.dumps({"ok":False,"result":"RUNNER_REREGISTRATION_BLOCKED",
              "error_type":type(e).__name__,"state":state,"token_persisted":False,
              "actions_qualified":False,"hml_verified":False,
              "token_logged":False},sort_keys=True)); return 3
if __name__=="__main__": raise SystemExit(main())
