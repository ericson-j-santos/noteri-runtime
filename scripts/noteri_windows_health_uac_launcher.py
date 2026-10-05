#!/usr/bin/env python3
from __future__ import annotations
import argparse,ctypes,json,os,subprocess,time
from pathlib import Path
CONFIRM="LAUNCH-NOTERI-WINDOWS-HEALTH-UAC"
WORKER_CONFIRM="RUN-NOTERI-WINDOWS-HEALTH"
def powershell_runas(executable:Path,params:str,cwd:Path)->str:
 ps=Path(os.environ.get("SystemRoot") or r"C:\\Windows")/"System32"/"WindowsPowerShell"/"v1.0"/"powershell.exe"
 if not ps.is_file(): return "missing"
 script=("$ErrorActionPreference='Stop';"
         f"$p=Start-Process -FilePath {json.dumps(str(executable))} -ArgumentList {json.dumps(params)} "
         f"-WorkingDirectory {json.dumps(str(cwd))} -Verb RunAs -PassThru;"
         "if($null -eq $p){exit 2}else{exit 0}")
 try:
  r=subprocess.run([str(ps),"-NoProfile","-ExecutionPolicy","Bypass","-Command",script],
   capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30,check=False)
 except subprocess.TimeoutExpired:
  return "timeout"
 return "launched" if r.returncode==0 else "failed"

def shell_application_runas(executable:Path,params:str,cwd:Path)->str:
 ps=Path(os.environ.get("SystemRoot") or r"C:\\Windows")/"System32"/"WindowsPowerShell"/"v1.0"/"powershell.exe"
 if not ps.is_file(): return "missing"
 script="$ErrorActionPreference='Stop';$s=New-Object -ComObject Shell.Application;"
         f"$s.ShellExecute({json.dumps(str(executable))},{json.dumps(params)},{json.dumps(str(cwd))},'runas',1);"
         "Start-Sleep -Milliseconds 500;exit 0")
 try:
  r=subprocess.run([str(ps),"-NoProfile","-ExecutionPolicy","Bypass","-Command",script],
   capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30,check=False)
 except subprocess.TimeoutExpired:
  return "timeout"
 return "launched" if r.returncode==0 else "failed"

def main():
 p=argparse.ArgumentParser();p.add_argument("--worker",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True);p.add_argument("--confirm",required=True);p.add_argument("--timeout",type=int,default=180);a=p.parse_args()
 if a.confirm!=CONFIRM or not a.worker.is_file(): print(json.dumps({"ok":False,"state":"launch_failed"}));return 2
 try:a.receipt.unlink()
 except FileNotFoundError:pass
 params=subprocess.list2cmdline([str(a.worker),"--confirm",WORKER_CONFIRM,"--receipt",str(a.receipt)])
 rc=int(ctypes.windll.shell32.ShellExecuteW(None,"runas",os.sys.executable,params,str(a.worker.parent),1))
 attempts={"shell_execute":"launched" if rc>32 else f"denied:{rc}","powershell":"not_run","shell_application":"not_run"}
 broker="shell_execute_runas" if rc>32 else "none"
 if rc<=32:
  attempts["powershell"]=powershell_runas(Path(os.sys.executable),params,a.worker.parent)
  if attempts["powershell"]=="launched": broker="powershell_start_process_runas"
  else:
   attempts["shell_application"]=shell_application_runas(Path(os.sys.executable),params,a.worker.parent)
   if attempts["shell_application"]=="launched": broker="shell_application_runas"
 if broker=="none": print(json.dumps({"ok":False,"state":"launch_failed","attempts":attempts,"fallbacks_exhausted":True}));return 3
 end=time.monotonic()+max(15,min(a.timeout,300))
 while time.monotonic()<end:
  if a.receipt.is_file():
   try:r=json.loads(a.receipt.read_text(encoding="utf-8"))
   except Exception:r={}
   print(json.dumps({"ok":bool(r.get("ok")),"state":"completed","worker_state":r.get("state"),"receipt":str(a.receipt),"broker":broker,"attempts":attempts}));return 0 if r.get("ok") else 4
  time.sleep(1)
 print(json.dumps({"ok":False,"state":"approval_or_execution_pending","receipt":str(a.receipt),"broker":broker,"attempts":attempts}));return 5
if __name__=="__main__":raise SystemExit(main())
