"""Synthetic gates; no DB, Win32 or network access in unit tests."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import importlib.util
import pytest

FILE=Path(__file__).resolve().parents[1]/"scripts"/"noteri_pg18_readonly.py"
spec=importlib.util.spec_from_file_location("noteri_pg18_readonly",FILE)
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

def env(folder,now):
    return {"NOTERI_PG_ADMITTED_AT":now.isoformat(),
      "EXPECTED_SOURCE_SHA":"a"*40,"RULES_SHA":"b"*40,"GITHUB_RUN_ID":"123",
      "GITHUB_RUN_ATTEMPT":"1","GITHUB_ACTIONS":"true","GITHUB_REPOSITORY":s.REPO,
      "GITHUB_EVENT_NAME":"pull_request","GITHUB_HEAD_REF":s.BRANCH,
      "GITHUB_ACTOR":"ericson-j-santos","COMPUTERNAME":"Noteri",
      "RUNNER_NAME":"Noteri","RUNNER_OS":"Windows","RUNNER_ARCH":"X64",
      "SESSION_LAUNCH_RESULT":"SESSION_LAUNCH_OK",
      "SESSION_STATE_VALIDATED":"true","SESSION_TARGET_PATH":str(folder)}

def sample():
    return {"pg_version":"18","install_present":True,"binaries_present":True,
      "data_directory_present":True,"postmaster_marker_present":True,
      "service_state":"running"}

def test_pass_and_replay_are_readonly(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);now=datetime.now(timezone.utc)
    e=env(tmp_path,now)
    x=s.collect(e,"Noteri","win32",sample,now)
    assert x==s.collect(e,"Noteri","win32",sample,now)
    assert x["native_binary_installed"]
    assert not x["db_connected"] and not x["tls_verified"]
    assert not x["shared_authority_verified"] and not x["ready_for_pr"]
    assert not x["docker_used"] and not x["external_db_used"]

@pytest.mark.parametrize("field,value",[
("GITHUB_REPOSITORY","other/repo"),("GITHUB_EVENT_NAME","workflow_dispatch"),
("GITHUB_ACTOR","other"),("RUNNER_NAME","desktop"),
("GITHUB_HEAD_REF","main"),("EXPECTED_SOURCE_SHA","invalid"),
("RUNNER_OS","Linux"),("SESSION_LAUNCH_RESULT","blocked"),
("SESSION_STATE_VALIDATED","false"),("GITHUB_RUN_ATTEMPT","2")])
def test_invalid_provenance_prevents_os_probe(tmp_path,monkeypatch,field,value):
    monkeypatch.chdir(tmp_path);now=datetime.now(timezone.utc)
    e=env(tmp_path,now);e[field]=value
    reached=[]
    def wrong():reached.append(True);return sample()
    with pytest.raises(s.Blocked):
        s.collect(e,"Noteri","win32",wrong,now)
    assert not reached

def test_expired_admission_fails(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);now=datetime.now(timezone.utc)
    with pytest.raises(s.Blocked):
        s.collect(env(tmp_path,now-timedelta(seconds=301)),"Noteri",
                  "win32",sample,now)

def test_extra_fields_rejected(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path);now=datetime.now(timezone.utc)
    def wrong():return {**sample(),"exposed_path":"private"}
    with pytest.raises(s.Blocked):
        s.collect(env(tmp_path,now),"Noteri","win32",wrong,now)

def test_source_has_no_mutation_or_shell():
    raw=FILE.read_text("utf-8")
    for denied in ("subprocess.run", "os.system(", "psql -c", "StartServiceW(",
                   "ControlService(", "winreg.SetValue", "postgresql://",
                   "socket.socket(","Neon","DockerClient"):
        assert denied not in raw
    assert "QueryServiceStatusEx" in raw
