"""Testes do contrato antes de habilitar execucao em host real."""
from __future__ import annotations
import importlib.util
import hashlib
from pathlib import Path
import pytest

MODULE=Path(__file__).resolve().parents[1]/"scripts"/"noteri_watchdog_transactional_upgrade.py"
spec=importlib.util.spec_from_file_location("noteri_watchdog_transactional_upgrade",MODULE)
m=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=m
spec.loader.exec_module(m)

OLD="a"*40
NEW="b"*40
old=b"release-original"
new=b"release-new"
hash_old=hashlib.sha256(old).hexdigest()
hash_new=hashlib.sha256(new).hexdigest()


def req():
    return m.Request(OLD,hash_old,NEW,hash_new,"noteri-transaction-20261115")


class Fake:
    def __init__(self, fail=False, rollback_fail=False):
        self.snap=m.Snapshot(OLD,hash_old,b'{"old":true}',b"<Task>original</Task>",old)
        self.before=self.snap
        self.install_calls=0
        self.restore_calls=0
        self.fail=fail
        self.rollback_fail=rollback_fail
    def inspect(self): return self.snap
    def verify_source(self,r):
        if r.target_sha!=NEW: raise m.UpgradeBlocked("SOURCE_REJECTED")
    def install(self,r):
        self.install_calls+=1
        self.snap=m.Snapshot(NEW,hash_new,b'{"new":true}',b"<Task>updated</Task>",new)
        if self.fail: raise RuntimeError("FAULT_INJECTED_AFTER_TASK_CHANGE")
    def restore(self, old):
        self.restore_calls+=1
        if self.rollback_fail: raise RuntimeError("ROLLBACK_SIMULATED_FAILURE")
        self.snap=old


def test_readonly_preflight_does_not_write(tmp_path):
    a=Fake();result=m.transact(a,req(),tmp_path,authorized=False)
    assert result["result"]=="PREFLIGHT_OK_NOT_AUTHORIZED"
    assert a.install_calls==0 and not list(tmp_path.iterdir())


def test_valid_upgrade_writes_private_verified_backup_and_readback(tmp_path):
    a=Fake();result=m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert result["result"]=="UPGRADE_VERIFIED" and result["state_changed"]
    assert a.install_calls==1 and a.restore_calls==0
    b=tmp_path/"backups"/"upgrade-noteri-transaction-20261115"
    assert (b/"task.xml").read_bytes()==a.before.task_xml
    assert (b/"metadata.json").read_bytes()==a.before.metadata
    assert (b/"old-release.py").read_bytes()==old
    assert len(result["backup_manifest_sha256"])==64


def test_replay_is_idempotent_with_no_new_backup(tmp_path):
    a=Fake();m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    result=m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert result["result"]=="ALREADY_CURRENT" and result["state_changed"] is False
    assert a.install_calls==1


def test_failure_after_task_mutation_restores_old_state(tmp_path):
    a=Fake(fail=True)
    with pytest.raises(m.UpgradeBlocked,match="UPGRADE_FAILED_ROLLED_BACK"):
        m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert a.inspect()==a.before and a.restore_calls==1
    assert (tmp_path/"backups"/"upgrade-noteri-transaction-20261115"/"manifest.json").is_file()


def test_rollback_failure_remains_blocked_and_preserves_backup(tmp_path):
    a=Fake(fail=True,rollback_fail=True)
    with pytest.raises(m.UpgradeBlocked,match="ROLLBACK_FAILED_MANUAL_RECOVERY_REQUIRED"):
        m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert (tmp_path/"backups"/"upgrade-noteri-transaction-20261115"/"task.xml").is_file()


@pytest.mark.parametrize("bad",[
    m.Request("x",hash_old,NEW,hash_new,"noteri-transaction-20261115"),
    m.Request(OLD,"x",NEW,hash_new,"noteri-transaction-20261115"),
    m.Request(OLD,hash_old,OLD,hash_new,"noteri-transaction-20261115"),
    m.Request(OLD,hash_old,NEW,hash_new,"../injection"),
])
def test_invalid_request_fails_before_any_operation(tmp_path,bad):
    a=Fake()
    with pytest.raises(m.UpgradeBlocked): m.transact(a,bad,tmp_path,authorized=True,confirm=m.CONFIRM)
    assert not list(tmp_path.iterdir()) and a.install_calls==0


def test_wrong_previous_sha_or_digest_fail_closed(tmp_path):
    a=Fake()
    bad=m.Request("c"*40,hash_old,NEW,hash_new,"noteri-transaction-20261115")
    with pytest.raises(m.UpgradeBlocked,match="PREVIOUS_VERSION_MISMATCH"):
        m.transact(a,bad,tmp_path,authorized=True,confirm=m.CONFIRM)
    assert a.install_calls==0


def test_wrong_confirm_does_not_mutate(tmp_path):
    a=Fake()
    with pytest.raises(m.UpgradeBlocked,match="EXPLICIT_CONFIRMATION_REQUIRED"):
        m.transact(a,req(),tmp_path,authorized=True,confirm="incorrect")
    assert a.install_calls==0 and not list(tmp_path.iterdir())


def test_existing_backup_is_not_overwritten(tmp_path):
    a=Fake();m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    a.snap=a.before
    with pytest.raises(FileExistsError): m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert a.install_calls==1


def test_detects_tampered_backup_root(tmp_path):
    a=Fake();outside=tmp_path/"outside";outside.mkdir();root=tmp_path/"root";root.mkdir()
    try: (root/"backups").symlink_to(outside,target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip("symlink unavailable")
    with pytest.raises(m.UpgradeBlocked,match="BACKUP_ROOT_REDIRECTED"):
        m.transact(a,req(),root,authorized=True,confirm=m.CONFIRM)
    assert a.install_calls==0


def test_task_xml_requires_boot_s4u_and_exact_action(tmp_path):
    args=m.subprocess.list2cmdline([r"C:\release\watchdog.py", "watch", "--runner-home", r"C:\runner"])
    xml=f'''<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><BootTrigger/></Triggers><Principals><Principal><LogonType>S4U</LogonType></Principal></Principals><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Arguments>{args}</Arguments></Exec></Actions></Task>''' 
    m._task_contract(xml.encode(),Path(r"C:\release\watchdog.py"),Path(r"C:\runner"))
    for changed in [xml.replace("S4U","Password"),xml.replace("BootTrigger","LogonTrigger"),xml.replace("watch --runner-home","other --runner-home"),xml.replace("<Enabled>true", "<Enabled>false")]:
        with pytest.raises(m.UpgradeBlocked):
            m._task_contract(changed.encode(),Path(r"C:\release\watchdog.py"),Path(r"C:\runner"))


def test_exclusive_lease_rejects_concurrent_upgrade(tmp_path):
    (tmp_path/"upgrade.lock").write_text("other-lease")
    a=Fake()
    with pytest.raises(FileExistsError):
        m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert a.install_calls==0


def test_rollback_failure_preserves_lock_for_manual_recovery(tmp_path):
    a=Fake(fail=True,rollback_fail=True)
    with pytest.raises(m.UpgradeBlocked,match="ROLLBACK_FAILED_MANUAL_RECOVERY_REQUIRED"):
        m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
    assert (tmp_path/"upgrade.lock").read_text().startswith("LOCKED_UPGRADE")
    with pytest.raises(FileExistsError):
        m.transact(a,req(),tmp_path,authorized=True,confirm=m.CONFIRM)
