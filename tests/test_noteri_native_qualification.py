"""Readback tests use temporary files; Windows inventory must be tested on Noteri."""
import importlib.util
import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/"scripts"/"noteri_native_qualification.py"
spec=importlib.util.spec_from_file_location("qualification", SOURCE)
q=importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)

class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.install=Path(self.temp.name)/"install"
        self.backup=self.install/"backup-fixture"
        self.backup.mkdir(parents=True)
        self.entries={}
        for i,rel in enumerate(sorted(q.MANAGED)):
            data=f"previous-{i}".encode()
            target=self.install/rel
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
            saved=self.backup/"files"/rel
            saved.parent.mkdir(parents=True,exist_ok=True)
            saved.write_bytes(data)
            self.entries[rel]={"existed":True,"previous_sha256":hashlib.sha256(data).hexdigest(),
                "previous_size":len(data),"previous_mode":stat.S_IMODE(target.stat().st_mode)}
        self.manifest={"version":1,"install_root":str(self.install),"entries":self.entries}
        self.write()
        (self.install/"update-receipt.json").write_text(json.dumps({"backup_dir":str(self.backup)}))
    def write(self):
        (self.backup/"rollback-manifest.json").write_text(json.dumps(self.manifest))
    def test_complete_previous_state_is_verified_without_write(self):
        before={str(p):p.read_bytes() for p in self.install.rglob("*") if p.is_file()}
        self.assertTrue(q.rollback_readback(self.install)["matches_previous"])
        after={str(p):p.read_bytes() for p in self.install.rglob("*") if p.is_file()}
        self.assertEqual(before,after)
    def test_changed_installed_file_is_not_false_success(self):
        (self.install/"bin/session_launcher.py").write_bytes(b"newer")
        self.assertFalse(q.rollback_readback(self.install)["matches_previous"])
    def test_corrupted_backup_blocks_match(self):
        (self.backup/"files/bin/session_launcher.py").write_bytes(b"altered")
        self.assertFalse(q.rollback_readback(self.install)["matches_previous"])
    def test_absent_before_and_after_matches(self):
        rel="bin/runner_version_preflight.py"
        (self.install/rel).unlink()
        self.entries[rel]={"existed":False}
        self.write()
        self.assertTrue(q.rollback_readback(self.install)["matches_previous"])
    def test_new_file_left_after_failure_is_detected(self):
        self.entries["bin/runner_version_preflight.py"]={"existed":False}
        self.write()
        self.assertFalse(q.rollback_readback(self.install)["matches_previous"])
    def test_missing_entry_rejected(self):
        self.entries.pop("bin/session_launcher.py")
        self.write()
        with self.assertRaises(q.Blocked): q.rollback_readback(self.install)
    def test_other_install_root_rejected(self):
        self.manifest["install_root"]=str(self.install.parent)
        self.write()
        with self.assertRaises(q.Blocked): q.rollback_readback(self.install)
    def test_symlink_rejected(self):
        target=self.install/"alias"
        target.symlink_to(self.install/"config/policy.json")
        with self.assertRaises(q.Blocked): q.read_regular(target)
    def test_oversized_input_rejected(self):
        target=self.install/"config/policy.json"
        with self.assertRaises(q.Blocked): q.read_regular(target,limit=1)
    def test_replay_is_deterministic(self):
        self.assertEqual(q.rollback_readback(self.install),q.rollback_readback(self.install))
    def test_bad_sha_rejected_before_process(self):
        with patch.object(q.subprocess,"run") as run:
            with self.assertRaises(q.Blocked):q.source_head("main")
        run.assert_not_called()
    def test_source_mismatch_blocks(self):
        with patch.object(q.subprocess,"run") as run:
            run.return_value.returncode=0
            run.return_value.stdout="b"*40
            with self.assertRaises(q.Blocked):q.source_head("a"*40)
    def test_no_shell_or_mutating_service_operations(self):
        source=SOURCE.read_text()
        self.assertNotIn("shell=True",source)
        for name in ("StartServiceW","ControlService","ChangeServiceConfig","CreateServiceW"):
            self.assertNotIn(name,source)

if __name__=="__main__":unittest.main()
