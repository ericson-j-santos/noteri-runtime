from pathlib import Path
import importlib.util,sys
import pytest
P=Path(__file__).resolve().parents[1]/"scripts"/"noteri_runner_reregister.py"
S=importlib.util.spec_from_file_location("noteri_runner_reregister",P); m=importlib.util.module_from_spec(S);sys.modules[S.name]=m;S.loader.exec_module(m)
def test_contract_fixed():
 assert m.EXPECTED_HOST=="Noteri"; assert m.EXPECTED_REPOSITORY=="ericson-j-santos/noteri-runtime"
 assert m.EXPECTED_LABELS==("noteri","reqsys-dev")
def test_rejects_wrong_host():
 with pytest.raises(m.BootstrapError): m.validate("OTHER",m.EXPECTED_REPOSITORY,m.CONFIRM)
def test_rejects_wrong_repo():
 with pytest.raises(m.BootstrapError): m.validate("Noteri","other/repo",m.CONFIRM)
def test_requires_ephemeral_token(tmp_path,monkeypatch):
 for p in ("config.cmd","run.cmd"):
  (tmp_path/p).write_text("",encoding="utf-8")
 (tmp_path/"bin").mkdir(); (tmp_path/"bin"/"Runner.Listener.exe").write_text("",encoding="utf-8")
 with pytest.raises(m.BootstrapError,match="token efemero"): m.configure(tmp_path,"")
def test_idempotent_marker(tmp_path):
 (tmp_path/".runner").write_text("configured",encoding="utf-8")
 assert m.configured(tmp_path)
