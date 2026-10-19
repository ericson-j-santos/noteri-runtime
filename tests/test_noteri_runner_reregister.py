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

def test_invalid_marker_is_not_idempotent_success(tmp_path):
 (tmp_path/".runner").write_text("configured",encoding="utf-8")
 with pytest.raises(m.BootstrapError, match="runner_marker_invalid"):
  m.configured(tmp_path)

# File/CLI tests below never obtain tokens, configure a runner or start a process.
import hashlib
import json

@pytest.fixture
def home(tmp_path):
 (tmp_path/'bin').mkdir()
 for name in ('config.cmd','run.cmd','bin/Runner.Listener.exe'):
  (tmp_path/name).write_bytes(b'fixture-not-executable')
 return tmp_path

def marker(home, **overrides):
 data={'gitHubUrl':m.EXPECTED_URL,'agentId':21,'agentName':m.EXPECTED_NAME,'workFolder':'_work'}
 data.update(overrides)
 path=home/'.runner'; path.write_text(json.dumps(data), encoding='utf-8')
 return path

def no_effects(monkeypatch):
 def forbidden(*a, **k):
  pytest.fail('forbidden registration or process side effect')
 for name in ('find_gh','registration_token','configure','start'):
  monkeypatch.setattr(m,name,forbidden)

def cli(monkeypatch, home, *extra):
 monkeypatch.setattr(m.socket,'gethostname',lambda:'Noteri')
 monkeypatch.setattr(sys,'argv',['registrar','--runner-home',str(home),'--confirm',m.CONFIRM,*extra])
 return m.main()

def test_local_identity_positive_and_no_raw_fields(home):
 p=marker(home,private='never-export')
 out=m.local_identity(home)
 assert out['marker_sha256']==hashlib.sha256(p.read_bytes()).hexdigest()
 assert out['repository']==m.EXPECTED_REPOSITORY
 assert 'never-export' not in json.dumps(out)

def test_missing_marker_is_absent_not_qualified(home):
 assert m.configured(home) is False

@pytest.mark.parametrize('url',[
 'https://github.com/ericson-j-santos/reqsys-v2-enterprise-real',
 'http://github.com/ericson-j-santos/noteri-runtime',
 'https://github.com.evil.invalid/ericson-j-santos/noteri-runtime',
 'https://user@github.com/ericson-j-santos/noteri-runtime',
 'https://github.com:443/ericson-j-santos/noteri-runtime',
 'https://github.com/ericson-j-santos/noteri-runtime?x=1',
 'https://github.com/ericson-j-santos/noteri-runtime#fragment',
 'https://github.com/ericson-j-santos/noteri-runtime\n',None,42,
])
def test_wrong_repository_never_qualifies(home,url):
 marker(home,gitHubUrl=url)
 with pytest.raises(m.BootstrapError,match='runner_repository_mismatch'): m.configured(home)

@pytest.mark.parametrize('fields',[{'agentId':True},{'agentId':0},{'agentId':'21'},{'agentName':'Other'}])
def test_agent_binding(home, fields):
 marker(home,**fields)
 with pytest.raises(m.BootstrapError,match='runner_agent_mismatch'): m.configured(home)

def test_workfolder_binding(home):
 marker(home,workFolder='../reqsys')
 with pytest.raises(m.BootstrapError,match='runner_workfolder_mismatch'): m.configured(home)

@pytest.mark.parametrize('raw',[b'',b'[]',b'{',b'\xff',b'x'*65537,
 b'{"agentId":21,"agentId":22}'])
def test_invalid_marker_shape(home, raw):
 (home/'.runner').write_bytes(raw)
 with pytest.raises(m.BootstrapError,match='runner_marker_invalid'): m.configured(home)

def test_marker_directory(home):
 (home/'.runner').mkdir()
 with pytest.raises(m.BootstrapError,match='runner_marker_invalid'): m.configured(home)

def test_symlink_marker_rejected(home):
 target=home/'target.json'; target.write_text('{}')
 (home/'.runner').symlink_to(target)
 with pytest.raises(m.BootstrapError,match='runner_path_reparse'): m.configured(home)

def test_symlink_parent_rejected_before_resolve(home):
 link=home.parent/(home.name+'-link'); link.symlink_to(home,target_is_directory=True)
 with pytest.raises(m.BootstrapError,match='runner_path_reparse'): m.validate_home(link)

def test_permission_error_is_not_absence(home,monkeypatch):
 marker(home)
 old=Path.stat
 def denied(p,*a,**k):
  if p.name=='.runner': raise PermissionError('private-detail')
  return old(p,*a,**k)
 monkeypatch.setattr(Path,'stat',denied)
 with pytest.raises(PermissionError): m.configured(home)

def test_repeat_local_inspection_preserves_bytes(home):
 p=marker(home); before=p.read_bytes(); first=m.local_identity(home)
 assert first==m.local_identity(home) and p.read_bytes()==before

def test_cli_wrong_repo_returns_failure_without_mutation(home,monkeypatch,capsys):
 p=marker(home,gitHubUrl='https://github.com/ericson-j-santos/reqsys-v2-enterprise-real')
 before=p.read_bytes(); no_effects(monkeypatch)
 assert cli(monkeypatch,home)==3
 out=json.loads(capsys.readouterr().out)
 assert out['state']=='runner_repository_mismatch' and not out['actions_qualified']
 assert p.read_bytes()==before

def test_cli_inspect_missing_never_registers(home,monkeypatch,capsys):
 no_effects(monkeypatch)
 assert cli(monkeypatch,home,'--inspect-only')==3
 assert json.loads(capsys.readouterr().out)['state']=='runner_marker_missing'

def test_cli_valid_local_configuration_not_actions_proof(home,monkeypatch,capsys):
 marker(home); no_effects(monkeypatch)
 assert cli(monkeypatch,home,'--inspect-only')==0
 out=json.loads(capsys.readouterr().out)
 assert out['result']=='RUNNER_LOCAL_CONFIGURATION_VERIFIED'
 assert not out['actions_qualified'] and not out['hml_verified']

def test_configure_existing_blocks_before_token(home,monkeypatch):
 marker(home)
 monkeypatch.setattr(m,'registration_token',lambda *a:pytest.fail('must not get token'))
 with pytest.raises(m.BootstrapError,match='runner_configuration_exists'):m.configure(home,Path('gh'))

def test_configure_wrong_repo_blocks_before_token(home,monkeypatch):
 marker(home,gitHubUrl='https://github.com/ericson-j-santos/reqsys-v2-enterprise-real')
 monkeypatch.setattr(m,'registration_token',lambda *a:pytest.fail('must not get token'))
 with pytest.raises(m.BootstrapError,match='runner_repository_mismatch'):m.configure(home,Path('gh'))

def test_replace_flag_is_not_present():
 import ast
 constants=[x.value for x in ast.walk(ast.parse(P.read_text())) if isinstance(x,ast.Constant)]
 assert '--replace' not in constants

def test_inspect_installed_is_read_only(home,tmp_path,monkeypatch,capsys):
 marker(home,gitHubUrl='https://github.com/ericson-j-santos/reqsys-v2-enterprise-real')
 local=tmp_path/'local'; directory=local/'ReqSys'/'NoteriControlPlaneWatchdog';directory.mkdir(parents=True)
 (directory/'metadata.json').write_text(json.dumps({'host':'Noteri','service':'reqsys-noteri-control-plane-watchdog','runner_home':str(home)}))
 monkeypatch.setenv('LOCALAPPDATA',str(local)); monkeypatch.setattr(m.socket,'gethostname',lambda:'Noteri')
 monkeypatch.setattr(sys,'argv',['registrar','--inspect-installed','--confirm',m.CONFIRM]);no_effects(monkeypatch)
 assert m.main()==3
 assert json.loads(capsys.readouterr().out)['state']=='runner_repository_mismatch'


def test_injected_runner_inputs_are_removed(monkeypatch):
 monkeypatch.setenv('ACTIONS_RUNNER_INPUT_URL','https://other.invalid')
 monkeypatch.setenv('actions_runner_input_token','fixture')
 env=m.gh_env()
 assert not any(k.upper().startswith('ACTIONS_RUNNER_INPUT_') for k in env)
 assert env['GH_HOST']=='github.com'


def test_registration_input_is_child_environment_only(home,monkeypatch):
 value='synthetic-value-not-a-credential'
 monkeypatch.setattr(m,'registration_token',lambda *a:value)
 captured={}
 def fake_config(args,**kwargs):
  assert value not in args and '--token' not in args and '--replace' not in args
  assert kwargs['env']['ACTIONS_RUNNER_INPUT_TOKEN']==value
  assert 'ACTIONS_RUNNER_INPUT_TOKEN' not in m.os.environ
  captured['env']=kwargs['env']
  marker(home)
  class Result: returncode=0
  return Result()
 monkeypatch.setattr(m.subprocess,'run',fake_config)
 m.configure(home,Path('gh-fixture'))
 assert 'ACTIONS_RUNNER_INPUT_TOKEN' not in captured['env']


def test_failed_configuration_clears_child_environment(home,monkeypatch):
 captured={}
 monkeypatch.setattr(m,'registration_token',lambda *a:'synthetic')
 def fail(args,**kwargs):
  captured['env']=kwargs['env']
  raise TimeoutError('private-error-not-exported')
 monkeypatch.setattr(m.subprocess,'run',fail)
 with pytest.raises(TimeoutError): m.configure(home,Path('gh-fixture'))
 assert 'ACTIONS_RUNNER_INPUT_TOKEN' not in captured['env']


def test_configuration_postcondition_rejects_wrong_repository(home,monkeypatch):
 monkeypatch.setattr(m,'registration_token',lambda *a:'synthetic')
 def wrong(args,**kwargs):
  marker(home,gitHubUrl='https://github.com/ericson-j-santos/reqsys-v2-enterprise-real')
  class Result: returncode=0
  return Result()
 monkeypatch.setattr(m.subprocess,'run',wrong)
 with pytest.raises(m.BootstrapError,match='runner_repository_mismatch'):
  m.configure(home,Path('gh-fixture'))


def test_read_does_not_touch_credentials(home,monkeypatch):
 marker(home)
 opened=[]; original=Path.open
 def observed(path,*args,**kwargs):
  opened.append(path.name)
  return original(path,*args,**kwargs)
 monkeypatch.setattr(Path,'open',observed)
 assert m.configured(home)
 assert opened==['.runner']


def test_marker_change_during_read_is_rejected(home,monkeypatch):
 marker(home)
 original=m.os.fstat; calls=[]
 def changed(fd):
  item=original(fd); calls.append(fd)
  if len(calls)==2:
   class Stat:
    st_dev=item.st_dev; st_ino=item.st_ino; st_mode=item.st_mode
    st_size=item.st_size; st_mtime_ns=item.st_mtime_ns+1
   return Stat()
  return item
 monkeypatch.setattr(m.os,'fstat',changed)
 with pytest.raises(m.BootstrapError,match='runner_marker_changed'): m.configured(home)
