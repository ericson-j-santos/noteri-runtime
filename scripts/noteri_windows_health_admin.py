#!/usr/bin/env python3
from __future__ import annotations
import ctypes,json,os,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
CONFIRM="RUN-NOTERI-WINDOWS-HEALTH"
def admin(): return os.name=="nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())
def run(argv,timeout):
 r=subprocess.run(argv,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout,check=False)
 return {"exit_code":r.returncode}
def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument("--confirm",required=True);p.add_argument("--receipt",type=Path,required=True);a=p.parse_args()
 out={"schema":"noteri-windows-health/v1","host":os.environ.get("COMPUTERNAME",""),"elevated":admin(),"production_touched":False}
 if a.confirm!=CONFIRM or not admin(): out.update(ok=False,state="elevation_required")
 else:
  out["checkhealth"]=run(["dism.exe","/Online","/Cleanup-Image","/CheckHealth"],180)
  out["scanhealth"]=run(["dism.exe","/Online","/Cleanup-Image","/ScanHealth"],900)
  out["sfc_verifyonly"]=run(["sfc.exe","/verifyonly"],900)
  out["configci_present"]=bool(list(Path(os.environ["SystemRoot"]).glob("System32/WindowsPowerShell/v1.0/Modules/ConfigCI")))
  out["cipolicy_schema_present"]=(Path(os.environ["SystemRoot"])/"schemas"/"CodeIntegrity"/"cipolicy.xsd").is_file()
  out["ok"]=all(out[k]["exit_code"]==0 for k in ("checkhealth","scanhealth","sfc_verifyonly"))
  out["state"]="completed" if out["ok"] else "health_issue_detected"
 out["completed_at"]=datetime.now(timezone.utc).isoformat();a.receipt.parent.mkdir(parents=True,exist_ok=True)
 tmp=a.receipt.with_suffix(".tmp");tmp.write_text(json.dumps(out,sort_keys=True)+"\n",encoding="utf-8");os.replace(tmp,a.receipt)
 print(json.dumps({"ok":out.get("ok",False),"state":out.get("state"),"receipt":str(a.receipt)}));return 0 if out.get("ok") else 3
if __name__=="__main__":raise SystemExit(main())
