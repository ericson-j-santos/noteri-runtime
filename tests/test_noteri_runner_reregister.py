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
def test_registration_requires_expected_local_identity(monkeypatch):
 class CP:
  returncode=0; stdout="other-user\\n"
 monkeypatch.setattr(m.subprocess,"run",lambda *a,**k: CP())
 with pytest.raises(m.BootstrapError,match="github_identity_mismatch"):
  m.registration_token(Path("gh"))

def test_gh_env_removes_injected_tokens(monkeypatch):
 monkeypatch.setenv("GH_TOKEN","secret"); monkeypatch.setenv("GITHUB_TOKEN","secret2")
 env=m.gh_env()
 assert "GH_TOKEN" not in env and "GITHUB_TOKEN" not in env
def test_sanitized_states_do_not_include_secret_material():
 src=P.read_text(encoding="utf-8")
 assert '"state":state' in src
 assert '"token_logged":False' in src
 assert 'stdout' not in src[src.find('except Exception as e:'):]

def test_current_diag_classification_ignores_old_log(tmp_path):
 diag=tmp_path/"_diag"; diag.mkdir()
 old=diag/"Runner_old.log"; old.write_text("401 Bad credentials",encoding="utf-8")
 before=m.diag_snapshot(tmp_path)
 new=diag/"Runner_new.log"; new.write_text("Http response code: 403 Forbidden",encoding="utf-8")
 assert m.classify_current_diag(tmp_path,before)=="http_403"

def test_current_diag_returns_closed_categories(tmp_path):
 diag=tmp_path/"_diag"; diag.mkdir()
 before={}
 p=diag/"Runner_new.log"; p.write_text("unexpected internal detail SECRET",encoding="utf-8")
 assert m.classify_current_diag(tmp_path,before)=="runner_error"

def test_idempotent_marker(tmp_path):
 (tmp_path/".runner").write_text("configured",encoding="utf-8")
 assert m.configured(tmp_path)
