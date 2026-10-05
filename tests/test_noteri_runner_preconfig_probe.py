from pathlib import Path
import importlib.util,sys
P=Path(__file__).resolve().parents[1]/"scripts"/"noteri_runner_preconfig_probe.py"
S=importlib.util.spec_from_file_location("probe",P);m=importlib.util.module_from_spec(S);sys.modules[S.name]=m;S.loader.exec_module(m)
def test_probe_has_no_token_or_secret_access():
 src=P.read_text(encoding="utf-8").lower()
 assert "registration-token" not in src and "gh api" not in src
 assert '"token_used":false' in src
 assert "runner.listener.exe" in src
def test_contract_requires_listener(tmp_path):
 (tmp_path/"config.cmd").write_text("",encoding="utf-8")
 try:m.contract(tmp_path);assert False
 except RuntimeError as e:assert str(e)=="runner_home_incomplete"
