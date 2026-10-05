#!/usr/bin/env python3
"""Atuador administrativo governado do Noteri: sem shell/comando arbitrário."""
from __future__ import annotations
import argparse,ctypes,json,os,socket,subprocess
from datetime import datetime,timezone
from pathlib import Path
EXPECTED_HOST="Noteri"
CAPABILITIES={"windows-health","runner-probe","gateway-health","appcontrol-read"}
def elevated(): return os.name=="nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())
def run(argv,timeout=300):
 r=subprocess.run(argv,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout,check=False)
 return {"exit_code":r.returncode}
def execute(cap):
 if cap=="windows-health":
  return {"checkhealth":run(["dism.exe","/Online","/Cleanup-Image","/CheckHealth"],180),
          "scanhealth":run(["dism.exe","/Online","/Cleanup-Image","/ScanHealth"],900),
          "sfc_verifyonly":run(["sfc.exe","/verifyonly"],900)}
 if cap=="runner-probe":
  p=Path(r"C:\dev\actions-runner-noteri-2.337.0\bin\Runner.Listener.exe")
  return {"exists":p.is_file(),"version_probe":run([str(p),"--version"],30) if p.is_file() else None}
 if cap=="gateway-health":
  p=Path(r"C:\dev\chatgpt-command-gateway\bin\command_gateway.py")
  return {"gateway_present":p.is_file()}
 if cap=="appcontrol-read":
  p=Path(r"C:\Windows\System32\CodeIntegrity\CiPolicies\Active")
  return {"active_policy_files":sorted(x.name for x in p.glob("*.cip")) if p.is_dir() else []}
 raise RuntimeError("capability_not_allowed")
def main():
 p=argparse.ArgumentParser();p.add_argument("--capability",choices=sorted(CAPABILITIES),required=True);p.add_argument("--receipt",type=Path,required=True);a=p.parse_args()
 if socket.gethostname().casefold()!=EXPECTED_HOST.casefold() or not elevated():
  out={"ok":False,"state":"elevation_required"}
 else:
  try: out={"ok":True,"state":"completed","capability":a.capability,"result":execute(a.capability)}
  except Exception as e: out={"ok":False,"state":"capability_failed","error_type":type(e).__name__}
 out.update({"host":EXPECTED_HOST,"arbitrary_command":False,"completed_at":datetime.now(timezone.utc).isoformat()})
 a.receipt.parent.mkdir(parents=True,exist_ok=True);tmp=a.receipt.with_suffix(".tmp");tmp.write_text(json.dumps(out,sort_keys=True)+"\n",encoding="utf-8");os.replace(tmp,a.receipt)
 print(json.dumps({"ok":out["ok"],"state":out["state"],"capability":a.capability}));return 0 if out["ok"] else 3
if __name__=="__main__":raise SystemExit(main())
