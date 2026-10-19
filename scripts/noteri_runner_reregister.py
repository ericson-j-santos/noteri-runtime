#!/usr/bin/env python3
"""Bootstrap fail-closed para re-registro do GitHub Actions Runner no Noteri.

A inspeção local não registra, inicia ou reconfigura o runner. O marcador local
não comprova conectividade ou pickup no GitHub. O caminho legado de registro
continua separado; sua execução não foi homologada por este incremento.
"""
from __future__ import annotations
import argparse,json,os,shutil,socket,subprocess,time
import hashlib
import stat
from urllib.parse import urlsplit
from pathlib import Path

EXPECTED_HOST="Noteri"
EXPECTED_REPOSITORY="ericson-j-santos/noteri-runtime"
EXPECTED_URL="https://github.com/ericson-j-santos/noteri-runtime"
EXPECTED_NAME="Noteri"
EXPECTED_LABELS=("noteri","reqsys-dev")
CONFIRM="REREGISTER-NOTERI-RUNNER"
EXPECTED_GITHUB_LOGIN="ericson-j-santos"

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
        cmd=[str(root/"config.cmd"),"--unattended","--url",EXPECTED_URL,
             "--name",EXPECTED_NAME,"--labels",",".join(EXPECTED_LABELS),
             "--work","_work"]
        r=subprocess.run(cmd,cwd=str(root),env=child_env,capture_output=True,text=True,
                         encoding="utf-8",errors="replace",timeout=120,check=False)
    finally:
        child_env.pop("ACTIONS_RUNNER_INPUT_TOKEN",None)
        token=""
    if r.returncode!=0: raise BootstrapError(f"config_failed:{classify_current_diag(root,before)}")
    if not configured(root): raise BootstrapError("runner_marker_missing")

def start(root:Path)->None:
    try:
        subprocess.Popen([str(root/"run.cmd")],cwd=str(root),stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.DETACHED_PROCESS,
                         close_fds=True)
    except OSError as exc:
        raise BootstrapError("listener_failed") from exc

def main()->int:
    p=argparse.ArgumentParser()
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument("--runner-home",type=Path)
    source.add_argument("--inspect-installed",action="store_true")
    p.add_argument("--inspect-only",action="store_true")
    p.add_argument("--repository",default=EXPECTED_REPOSITORY); p.add_argument("--confirm",required=True)
    a=p.parse_args()
    try:
        validate(socket.gethostname(),a.repository,a.confirm)
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
                 "host invalido","repositorio invalido","confirmacao invalida")
        allowed += IDENTITY_ERRORS
        state=next((item for item in allowed if reason == item),"bootstrap_failed")
        print(json.dumps({"ok":False,"result":"RUNNER_REREGISTRATION_BLOCKED",
              "error_type":type(e).__name__,"state":state,"token_persisted":False,
              "actions_qualified":False,"hml_verified":False,
              "token_logged":False},sort_keys=True)); return 3
if __name__=="__main__": raise SystemExit(main())
