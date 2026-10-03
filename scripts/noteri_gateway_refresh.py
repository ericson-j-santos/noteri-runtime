#!/usr/bin/env python3
"""Atualizacao elevada e fail-closed do Command Gateway no host Noteri."""
from __future__ import annotations
import argparse, ctypes, hashlib, json, os, socket, subprocess, sys, tempfile, urllib.request
from pathlib import Path

EXPECTED_HOST="Noteri"
CONFIRM="REFRESH-NOTERI-COMMAND-GATEWAY"
RULES_REPO="ericson-j-santos/chatgpt-operational-rules"
RULES_COMMIT="d26351458b17c917100efc3b736dcc6d53a646cb"
RULES_VERSION="1.6.10"
INSTALL_SHA256="006c1e44ea96b58fe05c9cb7602298a0d99d45eca137f570baba2565de93e83c"
UPDATE_SHA256="c2f45c4b9ffbb7f1196abf49f3ca06ea6f9e041753b994e422f18683028c41c8"
INSTALL_ROOT=Path(r"C:\dev\chatgpt-command-gateway")
WORK_ROOT=Path(r"C:\dev\chatgpt-workers")

class RefreshError(RuntimeError): pass

def sha256(data: bytes)->str: return hashlib.sha256(data).hexdigest()
def validate(host:str, confirm:str, commit:str)->None:
    if host.casefold()!=EXPECTED_HOST.casefold(): raise RefreshError("host invalido")
    if confirm!=CONFIRM: raise RefreshError("confirmacao invalida")
    if commit!=RULES_COMMIT: raise RefreshError("commit divergente")

def fetch(path:str, expected:str)->bytes:
    url=f"https://raw.githubusercontent.com/{RULES_REPO}/{RULES_COMMIT}/scripts/{path}"
    req=urllib.request.Request(url,headers={"User-Agent":"Noteri-Gateway-Refresh/1"})
    with urllib.request.urlopen(req,timeout=30) as resp: data=resp.read(256*1024)
    if sha256(data)!=expected: raise RefreshError(f"hash divergente: {path}")
    return data

def receipt_ok()->bool:
    p=INSTALL_ROOT/"update-receipt.json"
    if not p.is_file(): return False
    try: d=json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError,json.JSONDecodeError): return False
    return d.get("result")=="HOST_UPDATE_OK" and d.get("source_commit")==RULES_COMMIT and d.get("rules_version")==RULES_VERSION

def run_elevated(confirm:str, commit:str)->dict:
    validate(socket.gethostname(),confirm,commit)
    if receipt_ok(): return {"ok":True,"result":"NOTERI_GATEWAY_ALREADY_CURRENT","source_commit":RULES_COMMIT,"rules_version":RULES_VERSION}
    install=fetch("install_command_gateway_host.py",INSTALL_SHA256)
    update=fetch("update_command_gateway_host.py",UPDATE_SHA256)
    with tempfile.TemporaryDirectory(prefix="noteri-gateway-refresh-") as td:
        root=Path(td); (root/"install_command_gateway_host.py").write_bytes(install); up=root/"update_command_gateway_host.py"; up.write_bytes(update)
        cmd=[sys.executable,str(up),"--commit",RULES_COMMIT,"--expected-self-sha256",UPDATE_SHA256,"--install-root",str(INSTALL_ROOT),"--work-root",str(WORK_ROOT)]
        if ctypes.windll.shell32.IsUserAnAdmin():
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=180,check=False)
        else:
            params=subprocess.list2cmdline(cmd[1:])
            rc=int(ctypes.windll.shell32.ShellExecuteW(None,"runas",cmd[0],params,str(root),1))
            if rc<=32: raise RefreshError(f"uac_launch_failed:{rc}")
            return {"ok":False,"result":"UAC_STARTED_READBACK_REQUIRED","source_commit":RULES_COMMIT}
        if r.returncode!=0: raise RefreshError(f"updater_failed:{r.returncode}:{r.stderr[-500:]}")
    if not receipt_ok(): raise RefreshError("readback invalido")
    return {"ok":True,"result":"NOTERI_GATEWAY_REFRESHED","source_commit":RULES_COMMIT,"rules_version":RULES_VERSION}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--confirm",required=True); p.add_argument("--commit",default=RULES_COMMIT); a=p.parse_args()
    try: out=run_elevated(a.confirm,a.commit)
    except Exception as e: out={"ok":False,"result":"NOTERI_GATEWAY_REFRESH_BLOCKED","error_type":type(e).__name__,"error":str(e)[:1000]}
    print(json.dumps(out,sort_keys=True)); return 0 if out.get("ok") else 3
if __name__=="__main__": raise SystemExit(main())
