"""Synthetic local runner metadata and sanitized log tests."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

class Blocked(ValueError):
    pass

def require(value, code):
    if not value:
        raise Blocked(code)

native = types.SimpleNamespace(
    read_json=lambda p: json.loads(p.read_text(encoding="utf-8")),
    read_regular=lambda p, *a: p.read_bytes())
admission = types.SimpleNamespace(
    require=require, guard=lambda *a: None, Blocked=Blocked,
    REPOSITORY="ericson-j-santos/noteri-runtime",
    RELATED="ericson-j-santos/reqsys-v2-enterprise-real", MAX_BYTES=1024*1024)
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("noteri_local_diagnostic_under_test",
    ROOT/"scripts/noteri_runner_local_diagnostic.py")
mod=importlib.util.module_from_spec(spec)
with patch.dict("sys.modules", {"noteri_native_qualification":native,
                               "noteri_actions_admission":admission}):
    spec.loader.exec_module(mod)

class LocalRunnerDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)/"runner"
        self.home.mkdir()
        self.meta = Path(self.tmp.name)/"metadata.json"
        self.meta.write_text(json.dumps({"host":"Noteri","runner_home":str(self.home)}))
        self.config=self.home/".runner"
        self.config.write_text(json.dumps({"agentId":21,"agentName":"Noteri",
                                         "gitHubUrl":"https://github.com/"+mod.RELATED,
                                         "sensitive_field":"must-never-export"}))
        (self.home/"_diag").mkdir()
        self.reader=patch.object(native,"read_regular",side_effect=lambda p,*a: p.read_bytes())
        self.reader.start()
        self.addCleanup(self.reader.stop)
    def inspect(self):
        return mod.local_runner_diagnostic(self.meta,True)
    def test_binds_real_configuration_without_exporting_opaque_fields(self):
        out=self.inspect()
        self.assertEqual(mod.RELATED,out["configured_repository"])
        self.assertEqual(21,out["configured_agent_id"])
        self.assertEqual("no_runner_log",out["log_status"])
        self.assertNotIn("must-never-export",json.dumps(out))
        self.assertFalse(out["actions_qualified"])
    def test_log_only_returns_classifications(self):
        (self.home/"_diag/Runner_test.log").write_text(
            "private-token Unauthorized TaskAgentSessionConflictException")
        out=self.inspect()
        self.assertTrue(out["log_markers"]["unauthorized"])
        self.assertTrue(out["log_markers"]["session_conflict"])
        self.assertNotIn("private-token",json.dumps(out))
    def test_listening_marker_never_proves_current_connectivity(self):
        (self.home/"_diag/Runner_test.log").write_text("Listening for Jobs")
        out=self.inspect()
        self.assertTrue(out["log_markers"]["listening_seen"])
        self.assertFalse(out["actions_qualified"])
    def test_wrong_metadata_host_blocks(self):
        self.meta.write_text(json.dumps({"host":"Desktop","runner_home":str(self.home)}))
        with self.assertRaisesRegex(mod.Blocked,"metadata_host"): self.inspect()
    def test_unknown_remote_is_not_promoted(self):
        self.config.write_text(json.dumps({"agentId":21,"agentName":"Noteri",
                                          "gitHubUrl":"https://other.invalid/repo"}))
        self.assertEqual("unrecognized",self.inspect()["configured_repository"])
    def test_missing_runner_file_does_not_mean_registration_absent(self):
        self.config.unlink()
        with self.assertRaises(FileNotFoundError): self.inspect()
    def test_never_reads_credentials_file(self):
        (self.home/".credentials").write_text("private-credential")
        out=self.inspect()
        self.assertNotIn("private-credential",json.dumps(out))
    def test_reads_latest_log_not_earlier_success(self):
        old=self.home/"_diag/Runner_old.log"; old.write_text("Listening for Jobs")
        os.utime(old,(1,1))
        (self.home/"_diag/Runner_new.log").write_text("Failed to create a session Unauthorized")
        out=self.inspect()
        self.assertTrue(out["log_markers"]["connection_failure"])
        self.assertFalse(out["log_markers"]["listening_seen"])

if __name__=="__main__": unittest.main()
