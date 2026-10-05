#!/usr/bin/env python3
"""Bootstrap fail-closed para re-registro do GitHub Actions Runner no Noteri.

O token efêmero é recebido somente por variável de ambiente e nunca é persistido
nem incluído em receipts/logs deste wrapper.
"""
from __future__ import annotations
import argparse,json,os,shutil,socket,subprocess,time
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

def validate_home(root:Path)->Path:
    root=root.resolve()
    for p in (root/"config.cmd",root/"run.cmd",root/"bin"/"Runner.Listener.exe"):
        if not p.is_file(): raise BootstrapError("runner_home incompleto")
    return root

def configured(root:Path)->bool:
    return (root/".runner").is_file()

def gh_env():
    env=dict(os.environ); env.pop("GH_TOKEN",None); env.pop("GITHUB_TOKEN",None); return env

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

def configure(root:Path,gh:Path)->None:
    token=registration_token(gh)
    try:
        cmd=[str(root/"config.cmd"),"--unattended","--replace","--url",EXPECTED_URL,
             "--token",token,"--name",EXPECTED_NAME,"--labels",",".join(EXPECTED_LABELS),
             "--work","_work"]
        r=subprocess.run(cmd,cwd=str(root),env=gh_env(),capture_output=True,text=True,
                         encoding="utf-8",errors="replace",timeout=120,check=False)
    finally:
        token=""
    if r.returncode!=0: raise BootstrapError(f"config_failed:{r.returncode}")
    if not configured(root): raise BootstrapError("registro nao materializou .runner")

def start(root:Path)->None:
    try:
        subprocess.Popen([str(root/"run.cmd")],cwd=str(root),stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.DETACHED_PROCESS,
                         close_fds=True)
    except OSError as exc:
        raise BootstrapError("listener_failed") from exc

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--runner-home",type=Path,required=True)
    p.add_argument("--repository",default=EXPECTED_REPOSITORY); p.add_argument("--confirm",required=True)
    a=p.parse_args()
    try:
        validate(socket.gethostname(),a.repository,a.confirm); root=validate_home(a.runner_home)
        if configured(root):
            out={"ok":True,"result":"RUNNER_ALREADY_CONFIGURED","host":EXPECTED_HOST,
                 "repository":EXPECTED_REPOSITORY,"token_persisted":False}
        else:
            gh=find_gh(); configure(root,gh); start(root)
            out={"ok":True,"result":"RUNNER_REREGISTERED","host":EXPECTED_HOST,
                 "repository":EXPECTED_REPOSITORY,"labels":list(EXPECTED_LABELS),"token_persisted":False}
        print(json.dumps(out,sort_keys=True)); return 0
    except Exception as e:
        reason=str(e)
        allowed=("github_cli_missing","github_identity_mismatch","runner_admin_permission_required",
                 "runner_home incompleto","config_failed","runner_marker_missing","listener_failed",
                 "host invalido","repositorio invalido","confirmacao invalida")
        state=next((item for item in allowed if reason.startswith(item)),"bootstrap_failed")
        print(json.dumps({"ok":False,"result":"RUNNER_REREGISTRATION_BLOCKED",
              "error_type":type(e).__name__,"state":state,"token_persisted":False,
              "token_logged":False},sort_keys=True)); return 3
if __name__=="__main__": raise SystemExit(main())
