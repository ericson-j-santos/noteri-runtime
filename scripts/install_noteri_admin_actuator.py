#!/usr/bin/env python3
"""Instala tarefa administrativa fixa para o atuador governado do Noteri."""
from __future__ import annotations
import argparse,ctypes,json,os,socket,subprocess,sys
from pathlib import Path
TASK=r"\Automation\NoteriGovernedAdminActuator"
CONFIRM="INSTALL-NOTERI-GOVERNED-ADMIN-ACTUATOR"
def admin(): return os.name=="nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())
def main():
 p=argparse.ArgumentParser();p.add_argument("--actuator",type=Path,required=True);p.add_argument("--confirm",required=True);a=p.parse_args()
 if a.confirm!=CONFIRM or socket.gethostname().casefold()!="noteri" or not admin() or not a.actuator.is_file():
  print(json.dumps({"ok":False,"state":"install_blocked"}));return 3
 runtime=Path(os.environ["LOCALAPPDATA"])/"ReqSys"/"NoteriGovernedAdminActuator";runtime.mkdir(parents=True,exist_ok=True)
 target=runtime/"noteri_admin_actuator.py";target.write_bytes(a.actuator.read_bytes())
 # Tarefa fixa e elevada; ações reais continuam limitadas pelo choices do atuador.
 tr=subprocess.list2cmdline([sys.executable,str(target),"--capability","windows-health","--receipt",str(runtime/"scheduled-receipt.json")])
 r=subprocess.run(["schtasks.exe","/Create","/TN",TASK,"/TR",tr,"/SC","ONCE","/ST","23:59","/RL","HIGHEST","/F"],
  capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30,check=False)
 print(json.dumps({"ok":r.returncode==0,"state":"installed" if r.returncode==0 else "task_create_failed","task":TASK,"arbitrary_command":False}))
 return 0 if r.returncode==0 else 4
if __name__=="__main__":raise SystemExit(main())
