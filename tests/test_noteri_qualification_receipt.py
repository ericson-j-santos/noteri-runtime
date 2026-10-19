import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
SCRIPTS=Path(__file__).resolve().parents[1]/"scripts"
sys.path.insert(0,str(SCRIPTS))
import noteri_qualification_receipt as q

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.sha="a"*40
        self.rules="b"*40
        self.stamp=datetime.now(timezone.utc).isoformat()
        self.job={"id":9,"run_id":3,"run_attempt":1,"runner_id":5,
            "name":q.JOB_NAME,"head_sha":self.sha,"status":"completed",
            "conclusion":"success","labels":["self-hosted"],"runner_name":"Noteri",
            "completed_at":self.stamp,
            "steps":[{"name":q.STEP_NAME,"status":"completed","conclusion":"success"}]}
        self.receipt={"host":"Noteri","repository":q.REPO,"source_sha":self.sha,
            "rules_sha":self.rules,"run_id":3,"run_attempt":1,"runner_name":"Noteri",
            "profile":"NORMAL","correlation_id":"noteri-qualification-3-1",
            "session_result":"SESSION_LAUNCH_OK","state_validated":True,
            "gateway_ok":True,"auth_valid":True,"generated_at":self.stamp,
             "snapshot_sha256":"c"*64,"independent_effect_verified":True,
            "local_readback_at":self.stamp,"local_readback_sha256":"d"*64,
            "worktree_status_count":0,"hml_verified":False,
            "capabilities":{"platform":"Windows","native_inventory":"observed"},
            "observation":{"status":"observed","host":"Noteri","source_sha":self.sha,
               "correlation_id":"noteri-qualification-3-1","hml_verified":False,
               "mutations_executed":False,"secrets_read":False,"production_touched":False,"operating_profile":{"profile":"NORMAL","verified":True},
               "rollback":{"matches_previous":True,"state_verified":True}}}
    def bundle(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as z:z.writestr("receipt.json",json.dumps(self.receipt))
        data=stream.getvalue()
        asset={"name":"noteri-qualification-3-1","expired":False,
           "digest":"sha256:"+hashlib.sha256(data).hexdigest(),"workflow_run":{"head_sha":self.sha,"id":3}}
        return data,asset
    def validate(self):
        data,asset=self.bundle()
        return q.validate_bundle(self.job,asset,data,self.sha,self.rules,3,1)
    def test_positive_bound_artifact(self):
        result=self.validate()
        self.assertEqual(9,result["job_id"])
        self.assertTrue(result["independent_effect_verified"])
        self.assertFalse(result["observation"]["hml_verified"])
    def test_changed_archive_is_rejected(self):
        data,asset=self.bundle()
        with self.assertRaises(q.Blocked):q.validate_bundle(self.job,asset,data+b"x",self.sha,self.rules,3,1)
    def test_no_runner(self):
        self.job["runner_id"]=0
        with self.assertRaises(q.Blocked):self.validate()
    def test_skipped_qualification(self):
        self.job["steps"][0]["conclusion"]="skipped"
        with self.assertRaises(q.Blocked):self.validate()
    def test_stale_job(self):
        self.job["completed_at"]=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
        with self.assertRaises(q.Blocked):self.validate()
    def test_other_sha(self):
        self.receipt["source_sha"]="f"*40
        with self.assertRaises(q.Blocked):self.validate()
    def test_other_attempt(self):
        self.receipt["run_attempt"]=2
        with self.assertRaises(q.Blocked):self.validate()
    def test_estudo_blocks(self):
        self.receipt["profile"]="ESTUDO"
        with self.assertRaises(q.Blocked):self.validate()
    def test_unreconciled_runtime_blocks(self):
        self.receipt["observation"]["rollback"]["state_verified"]=False
        with self.assertRaises(q.Blocked):self.validate()
    def test_mutation_cannot_be_reported_as_readonly(self):
        self.receipt["observation"]["mutations_executed"]=True
        with self.assertRaises(q.Blocked):self.validate()
    def test_boolean_job_identifier_rejected(self):
        self.job["id"]=True
        with self.assertRaises(q.Blocked):self.validate()
    def test_unknown_profile_is_not_normal(self):
        self.receipt["observation"]["operating_profile"]={"verified":False}
        with self.assertRaises(q.Blocked):self.validate()
    def test_archive_with_extra_file_is_rejected(self):
        data,asset=self.bundle()
        stream=io.BytesIO(data)
        with zipfile.ZipFile(stream,"a") as z:z.writestr("extra","x")
        data=stream.getvalue();asset["digest"]="sha256:"+q.digest(data)
        with self.assertRaises(q.Blocked):q.validate_bundle(self.job,asset,data,self.sha,self.rules,3,1)
    def test_outside_actions_blocks_before_native_call(self):
        with patch.dict(q.os.environ,{},clear=True):
            with self.assertRaises(q.Blocked):q.context()
    def test_repeated_verification_does_not_modify_input(self):
        before=json.dumps(self.receipt,sort_keys=True)
        self.assertEqual(self.validate(),self.validate())
        self.assertEqual(before,json.dumps(self.receipt,sort_keys=True))
    def test_atomic_writer_cleanup_after_replace_failure(self):
        with tempfile.TemporaryDirectory() as t:
            with patch.object(q.os,"replace",side_effect=OSError):
                with self.assertRaises(OSError):q.write_atomic(Path(t)/"receipt.json",{})
            self.assertEqual([],list(Path(t).iterdir()))


class IntegrationTests(unittest.TestCase):
    setUp = ReceiptTests.setUp
    bundle = ReceiptTests.bundle
    validate = ReceiptTests.validate
    # Inherit the bound-artifact fixtures; external APIs/native calls are simulated.
    def test_parent_symlink_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            real=Path(d)/"real";real.mkdir()
            link=Path(d)/"link";link.symlink_to(real,target_is_directory=True)
            with self.assertRaises(q.Blocked):
                q.write_atomic(link/"decision.json",{"ready":True})
            self.assertEqual([],list(real.iterdir()))

    def test_missing_physical_readback_blocks(self):
        self.receipt["independent_effect_verified"]=False
        with self.assertRaises(q.Blocked):self.validate()

    def test_capability_inflation_is_rejected(self):
        self.receipt["capabilities"]["sqlserver.major"]="17"
        with self.assertRaises(q.Blocked):self.validate()

    def test_boolean_worktree_state_is_rejected(self):
        self.receipt["worktree_status_count"]=False
        with self.assertRaises(q.Blocked):self.validate()

    def test_foreign_context_replaces_old_success(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(q.os.environ,{},clear=True):
            target=Path(d)/"decision.json"
            q.write_atomic(target,{"ready":True})
            with self.assertRaises(q.Blocked):
                q.verify(Path(d),self.rules,target)
            self.assertFalse(json.loads(target.read_text())["ready"])

    def api_fixture(self):
        data,asset=self.bundle()
        asset["id"]=10
        self.job["html_url"]=f"https://github.com/{q.REPO}/actions/runs/3/job/9"
        return data,asset

    def test_full_artifact_to_selector_roundtrip_and_replay(self):
        import copy
        import types
        data,asset=self.api_fixture()
        calls=[]
        def read(path):
            calls.append(path)
            if "/attempts/" in path:return {"total_count":1,"jobs":[copy.deepcopy(self.job)]}
            if "/artifacts?" in path:return {"total_count":1,"artifacts":[copy.deepcopy(asset)]}
            return copy.deepcopy(self.job)
        def evaluate(payload):
            # Assert API-assigned identities reach the shared selector.
            proof=payload["hosts"][0]["transport_evidence"]
            self.assertEqual(5,proof["receipt"]["runner_id"])
            self.assertEqual(9,proof["receipt"]["job_id"])
            self.assertTrue(proof["receipt"]["independent_effect_verified"])
            self.assertEqual(q.digest(data),proof["artifact_sha256"])
            self.assertEqual(self.rules,payload["required_rules_sha"])
            return {"ready":True,"selected_host":"Noteri","hml_verified":False,"decision_only":True}
        selector=types.SimpleNamespace(evaluate=evaluate)
        with tempfile.TemporaryDirectory() as d,patch.object(q,"context",return_value=(self.sha,3,1,"noteri-qualification-3-1")),patch.object(q,"api_json",side_effect=read),patch.object(q,"api_bytes",return_value=data),patch.object(q,"rules_module"),patch.object(q.importlib,"import_module",return_value=selector):
            target=Path(d)/"decision.json"
            first=q.verify(Path(d),self.rules,target)
            self.assertEqual(first,json.loads(target.read_text()))
            second=q.verify(Path(d),self.rules,target)
            self.assertEqual(first,second)
            self.assertEqual(2,calls.count("/actions/jobs/9"))

    def test_failed_persistence_never_reuses_ready_result(self):
        import types
        data,asset=self.api_fixture()
        writes=[]
        def read(path):
            if "/attempts/" in path:return {"total_count":1,"jobs":[self.job]}
            if "/artifacts?" in path:return {"total_count":1,"artifacts":[asset]}
            return self.job
        def write(path,value):
            writes.append(dict(value))
            if len(writes)==1:raise OSError("controlled-output-failure")
        with patch.object(q,"context",return_value=(self.sha,3,1,"noteri-qualification-3-1")),patch.object(q,"api_json",side_effect=read),patch.object(q,"api_bytes",return_value=data),patch.object(q,"rules_module"),patch.object(q.importlib,"import_module",return_value=types.SimpleNamespace(evaluate=lambda _:{"ready":True,"selected_host":"Noteri"})),patch.object(q,"write_atomic",side_effect=write):
            with self.assertRaises(OSError):q.verify(Path("."),self.rules,Path("unused"))
        self.assertTrue(writes[0]["ready"])
        self.assertFalse(writes[-1]["ready"])

    def test_second_native_reader_rejects_service_drift(self):
        import copy
        import types
        record=copy.deepcopy(self.receipt)
        record.update(session_id="noteri-test")
        record["observation"].update(generated_at=self.stamp,sql={"state":"running"})
        observed=copy.deepcopy(record["observation"])
        observed["sql"]["state"]="stopped"
        session={"target_path":str(Path.cwd()),"session_id":"noteri-test","snapshot_sha256":"c"*64}
        cg=types.SimpleNamespace(load_policy=lambda _: {}, enforce_session=lambda *_:None,
            git_state=lambda *_:types.SimpleNamespace(head=self.sha,status_count=0))
        with patch.object(q,"context",return_value=(self.sha,3,1,"noteri-qualification-3-1")),patch.object(q.native,"read_json",side_effect=[record,session]),patch.object(q,"rules_module",return_value=cg),patch.object(q.native,"collect",return_value=observed),patch.object(q,"write_atomic") as write:
            with self.assertRaises(q.Blocked):q.local_readback(Path("."),self.rules,Path("s"),Path("r"))
        write.assert_not_called()

    def test_second_native_reader_marks_matching_state(self):
        import copy
        import types
        record=copy.deepcopy(self.receipt)
        record.update(session_id="noteri-test",independent_effect_verified=False)
        record["observation"]["generated_at"]=self.stamp
        session={"target_path":str(Path.cwd()),"session_id":"noteri-test","snapshot_sha256":"c"*64}
        cg=types.SimpleNamespace(load_policy=lambda _: {}, enforce_session=lambda *_:None,
            git_state=lambda *_:types.SimpleNamespace(head=self.sha,status_count=0))
        with patch.object(q,"context",return_value=(self.sha,3,1,"noteri-qualification-3-1")),patch.object(q.native,"read_json",side_effect=[record,session]),patch.object(q,"rules_module",return_value=cg),patch.object(q.native,"collect",return_value=record["observation"]),patch.object(q,"write_atomic") as write:
            result=q.local_readback(Path("."),self.rules,Path("s"),Path("r"))
        self.assertTrue(result["local_readback_verified"])
        self.assertTrue(write.call_args.args[1]["independent_effect_verified"])

    def test_workflow_is_manual_pinned_and_readback_is_hosted(self):
        text=(SCRIPTS.parent/".github/workflows/noteri-control-plane-probe.yml").read_text()
        self.assertIn("workflow_dispatch:",text)
        self.assertNotIn("pull_request:",text)
        self.assertNotIn("  push:",text)
        self.assertNotIn("schedule:",text)
        self.assertIn("needs: probe",text)
        self.assertIn("runs-on: ubuntu-latest",text)
        self.assertIn("actions: read",text)
        self.assertIn(q.STEP_NAME,text)
        self.assertIn("python3 -B",text)
        self.assertIn("515b52b2ec51aa60f02265bd5a1e6df057140ece",text)

    def test_launch_routes_both_processes_through_gateway(self):
        import inspect
        text=inspect.getsource(q.launch)
        self.assertIn('("produce", "local-readback")',text)
        self.assertIn("cg.execute",text)
        self.assertIn("--require-runner-version-preflight",text)
        self.assertNotIn("StartService",text)

if __name__=="__main__":unittest.main()
