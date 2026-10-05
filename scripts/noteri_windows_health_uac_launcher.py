#!/usr/bin/env python3
from __future__ import annotations
import argparse,ctypes,json,os,subprocess,time
from pathlib import Path
CONFIRM="LAUNCH-NOTERI-WINDOWS-HEALTH-UAC"
WORKER_CONFIRM="RUN-NOTERI-WINDOWS-HEALTH"
def main():
 p=argparse.ArgumentParser();p.add_argument("--worker",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True);p.add_argument("--confirm",required=True);p.add_argument("--timeout",type=int,default=180);a=p.parse_args()
 if a.confirm!=CONFIRM or not a.worker.is_file(): print(json.dumps({"ok":False,"state":"launch_failed"}));return 2
 try:a.receipt.unlink()
 except FileNotFoundError:pass
 params=subprocess.list2cmdline([str(a.worker),"--confirm",WORKER_CONFIRM,"--receipt",str(a.receipt)])
 rc=int(ctypes.windll.shell32.ShellExecuteW(None,"runas",os.sys.executable,params,str(a.worker.parent),1))
 if rc<=32: print(json.dumps({"ok":False,"state":"launch_failed","broker_code":rc}));return 3
 end=time.monotonic()+max(15,min(a.timeout,300))
 while time.monotonic()<end:
  if a.receipt.is_file():
   try:r=json.loads(a.receipt.read_text(encoding="utf-8"))
   except Exception:r={}
   print(json.dumps({"ok":bool(r.get("ok")),"state":"completed","worker_state":r.get("state"),"receipt":str(a.receipt)}));return 0 if r.get("ok") else 4
  time.sleep(1)
 print(json.dumps({"ok":False,"state":"approval_or_execution_pending","receipt":str(a.receipt)}));return 5
if __name__=="__main__":raise SystemExit(main())
