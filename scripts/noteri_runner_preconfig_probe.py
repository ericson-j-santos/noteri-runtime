#!/usr/bin/env python3
"""Probes sanitizados das fases anteriores ao registro do runner Noteri."""
from __future__ import annotations
import argparse,json,os,subprocess
from pathlib import Path

def contract(root:Path)->Path:
 root=root.resolve()
 for p in (root/"config.cmd",root/"bin"/"Runner.Listener.exe"):
  if not p.is_file(): raise RuntimeError("runner_home_incomplete")
 return root

def unblock_probe(root:Path)->str:
 ps=Path(os.environ.get("SystemRoot") or r"C:\Windows")/"System32"/"WindowsPowerShell"/"v1.0"/"powershell.exe"
 if not ps.is_file(): return "powershell_missing"
 r=subprocess.run([str(ps),"-NoLogo","-Sta","-NoProfile","-NonInteractive","-ExecutionPolicy","Unrestricted",
  "-Command",f"Get-ChildItem -LiteralPath '{root}' | Unblock-File | Out-Null"],capture_output=True,
  text=True,encoding="utf-8",errors="replace",timeout=30,check=False)
 return "ok" if r.returncode==0 else "unblock_failed"

def listener_probe(root:Path)->str:
 exe=root/"bin"/"Runner.Listener.exe"
 try:
  r=subprocess.run([str(exe),"--version"],cwd=str(root),capture_output=True,text=True,
   encoding="utf-8",errors="replace",timeout=30,check=False)
 except OSError: return "listener_start_failed"
 if r.returncode!=0: return "listener_exit_nonzero"
 return "ok" if bool(r.stdout.strip()) else "listener_no_version_output"

def main()->int:
 p=argparse.ArgumentParser();p.add_argument("--runner-home",type=Path,required=True);a=p.parse_args()
 try:
  root=contract(a.runner_home); u=unblock_probe(root); l=listener_probe(root)
  out={"ok":u=="ok" and l=="ok","unblock":u,"listener":l,"secrets_read":False,"token_used":False}
 except Exception as e:
  out={"ok":False,"unblock":"not_run","listener":"not_run","state":"runner_home_incomplete",
       "secrets_read":False,"token_used":False}
 print(json.dumps(out,sort_keys=True));return 0 if out["ok"] else 3
if __name__=="__main__": raise SystemExit(main())
