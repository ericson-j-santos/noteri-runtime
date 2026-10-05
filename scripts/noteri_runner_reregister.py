#!/usr/bin/env python3
"""Bootstrap fail-closed para re-registro do GitHub Actions Runner no Noteri.

O token efêmero é recebido somente por variável de ambiente e nunca é persistido
nem incluído em receipts/logs deste wrapper.
"""
from __future__ import annotations
import argparse,json,os,socket,subprocess,time
from pathlib import Path

EXPECTED_HOST="Noteri"
EXPECTED_REPOSITORY="ericson-j-santos/noteri-runtime"
EXPECTED_URL="https://github.com/ericson-j-santos/noteri-runtime"
EXPECTED_NAME="Noteri"
EXPECTED_LABELS=("noteri","reqsys-dev")
CONFIRM="REREGISTER-NOTERI-RUNNER"
TOKEN_ENV="NOTERI_RUNNER_REGISTRATION_TOKEN"

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

def configure(root:Path,token:str)->None:
    if not token or len(token)<20: raise BootstrapError("token efemero ausente/invalido")
    cmd=[str(root/"config.cmd"),"--unattended","--replace","--url",EXPECTED_URL,
         "--token",token,"--name",EXPECTED_NAME,"--labels",",".join(EXPECTED_LABELS),
         "--work","_work"]
    env=dict(os.environ); env[TOKEN_ENV]=""
    r=subprocess.run(cmd,cwd=str(root),env=env,capture_output=True,text=True,
                     encoding="utf-8",errors="replace",timeout=120,check=False)
    if r.returncode!=0: raise BootstrapError(f"config_failed:{r.returncode}")
    if not configured(root): raise BootstrapError("registro nao materializou .runner")

def start(root:Path)->None:
    subprocess.Popen([str(root/"run.cmd")],cwd=str(root),stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                     creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.DETACHED_PROCESS,
                     close_fds=True)

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
            token=os.environ.get(TOKEN_ENV,""); configure(root,token); start(root)
            out={"ok":True,"result":"RUNNER_REREGISTERED","host":EXPECTED_HOST,
                 "repository":EXPECTED_REPOSITORY,"labels":list(EXPECTED_LABELS),"token_persisted":False}
        print(json.dumps(out,sort_keys=True)); return 0
    except Exception as e:
        print(json.dumps({"ok":False,"result":"RUNNER_REREGISTRATION_BLOCKED",
              "error_type":type(e).__name__,"token_persisted":False},sort_keys=True)); return 3
if __name__=="__main__": raise SystemExit(main())
