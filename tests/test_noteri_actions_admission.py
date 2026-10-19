"""Synthetic API fixtures exercise admission, not physical runner execution."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def atomic(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)

native = types.SimpleNamespace(
    read_json=lambda p: json.loads(p.read_text(encoding="utf-8")),
    read_regular=lambda *a: b"installed-binary",
    profile=lambda: {"profile": "NORMAL", "verified": True},
    source_head=lambda sha: sha,
)
receipts = types.SimpleNamespace(write_atomic=atomic)
spec = importlib.util.spec_from_file_location("noteri_admission_under_test",
    ROOT / "scripts/noteri_actions_admission.py")
mod = importlib.util.module_from_spec(spec)
with patch.dict("sys.modules", {
    "noteri_native_qualification": native,
    "noteri_qualification_receipt": receipts,
}):
    spec.loader.exec_module(mod)

SHA = "a" * 40
CORR = "noteri-admission-test"
class Api:
    def __init__(self):
        self.posts = 0
        self.calls = []
        runner = {"id": 9, "name": "noteri-dev", "os": "windows", "status": "online",
                  "busy": False, "labels": [{"name": x} for x in sorted(mod.LABELS)]}
        self.runner = runner
        self.data = {
            "user": {"login": mod.OWNER},
            f"repos/{mod.REPOSITORY}/actions/runners?per_page=100": {"total_count": 1, "runners": [runner]},
            f"repos/{mod.RELATED}/actions/runners?per_page=100": {"total_count": 0, "runners": []},
            f"repos/{mod.REPOSITORY}/git/ref/heads/{mod.REF}": {"object": {"sha": SHA}},
            f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}":
                {"state": "active", "path": ".github/workflows/" + mod.WORKFLOW},
            f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/runs?per_page=100":
                {"total_count": 0, "workflow_runs": []},
            f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/dispatches":
                {"workflow_run_id": 123,
                 "run_url": f"https://api.github.com/repos/{mod.REPOSITORY}/actions/runs/123",
                 "html_url": f"https://github.com/{mod.REPOSITORY}/actions/runs/123"},
            f"repos/{mod.REPOSITORY}/actions/runs/123":
                {"id": 123, "head_sha": SHA, "event": "workflow_dispatch",
                 "path": ".github/workflows/" + mod.WORKFLOW, "status": "queued"},
        }
    def call(self, endpoint, post=False):
        self.calls.append((endpoint, post))
        self.posts += int(post)
        value = self.data[endpoint]
        if isinstance(value, Exception):
            raise value
        return value

class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.api = Api()
        self.addCleanup(self.tmp.cleanup)
    def dispatch(self, confirm=mod.CONFIRM):
        return mod.dispatch_once(self.api, SHA, CORR, self.root, confirm)
    def test_positive_submission_has_independent_readback_but_not_qualification(self):
        out = self.dispatch()
        self.assertTrue(out["readback_verified"])
        self.assertEqual(1, self.api.posts)
        self.assertFalse(out["actions_qualified"])
        self.assertFalse(out["hml_verified"])
        self.assertEqual("submitted", json.loads((self.root/(CORR+".json")).read_text())["state"])
        self.assertFalse((self.root/"dispatch.lock").exists())
    def test_confirmation_precedes_any_side_effect(self):
        with self.assertRaisesRegex(mod.Blocked, "confirmation"):
            self.dispatch("NO")
        self.assertEqual([], self.api.calls)
        self.assertEqual([], list(self.root.iterdir()))
    def test_estudo_blocks_without_api(self):
        with patch.object(native, "profile", return_value={"verified": True, "profile": "ESTUDO"}):
            with self.assertRaisesRegex(mod.Blocked, "normal_required"): self.dispatch()
        self.assertEqual(0, self.api.posts)
        self.assertEqual([], self.api.calls)
    def test_wrong_account_blocks(self):
        self.api.data["user"] = {"login":"other"}
        with self.assertRaisesRegex(mod.Blocked, "account"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_runner_offline_prevents_submission(self):
        self.api.runner["status"]="offline"
        with self.assertRaisesRegex(mod.Blocked, "runner_not_eligible"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_busy_runner_prevents_submission(self):
        self.api.runner["busy"]=True
        with self.assertRaisesRegex(mod.Blocked, "runner_not_eligible"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_incomplete_labels_prevent_submission(self):
        self.api.runner["labels"]=[{"name":"noteri"}]
        with self.assertRaisesRegex(mod.Blocked, "runner_not_eligible"): self.dispatch()
    def test_scope_does_not_transfer_between_repositories(self):
        primary=f"repos/{mod.REPOSITORY}/actions/runners?per_page=100"
        secondary=f"repos/{mod.RELATED}/actions/runners?per_page=100"
        self.api.data[secondary]=self.api.data[primary]
        self.api.data[primary]={"total_count":0,"runners":[]}
        out=mod.inspect(self.api)
        self.assertFalse(out["dispatch_eligible"])
        self.assertTrue(out["registries"][1]["noteri_runners"][0]["eligible"])
    def test_no_admin_is_not_empty_registry(self):
        key=f"repos/{mod.REPOSITORY}/actions/runners?per_page=100"
        self.api.data[key]=mod.Blocked("github_http_403")
        out=mod.inspect(self.api)
        self.assertEqual("github_http_403",out["registries"][0]["blocked"])
        self.assertNotIn("noteri_runners",out["registries"][0])
    def test_incomplete_registry_fails_closed(self):
        self.api.data[f"repos/{mod.REPOSITORY}/actions/runners?per_page=100"]["total_count"]=2
        with self.assertRaisesRegex(mod.Blocked,"runner_not_eligible"): self.dispatch()
    def test_boolean_id_not_accepted(self):
        self.api.runner["id"]=True
        with self.assertRaisesRegex(mod.Blocked,"runner_not_eligible"): self.dispatch()
    def test_ambiguous_candidates_block(self):
        row=self.api.data[f"repos/{mod.REPOSITORY}/actions/runners?per_page=100"]
        row.update(total_count=2,runners=[self.api.runner,dict(self.api.runner,id=10)])
        with self.assertRaisesRegex(mod.Blocked,"runner_not_eligible"): self.dispatch()
    def test_ref_drift_blocks(self):
        self.api.data[f"repos/{mod.REPOSITORY}/git/ref/heads/{mod.REF}"]["object"]["sha"]="b"*40
        with self.assertRaisesRegex(mod.Blocked,"ref_changed"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_disabled_workflow_blocks(self):
        self.api.data[f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}"]["state"]="disabled"
        with self.assertRaisesRegex(mod.Blocked,"workflow_not_approved"): self.dispatch()
    def test_existing_active_attempt_blocks_queue_duplication(self):
        self.api.data[f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/runs?per_page=100"]={
            "total_count":1,"workflow_runs":[{"status":"queued"}]}
        with self.assertRaisesRegex(mod.Blocked,"already_active"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_replay_preserves_receipt_and_does_not_post(self):
        first=self.dispatch()
        raw=(self.root/(CORR+".json")).read_bytes()
        second=self.dispatch()
        self.assertTrue(second["replayed"])
        self.assertFalse(second["submitted_by_this_call"])
        self.assertEqual(first["run_id"],second["run_id"])
        self.assertEqual(1,self.api.posts)
        self.assertEqual(raw,(self.root/(CORR+".json")).read_bytes())
    def test_uncertain_post_is_never_retried(self):
        key=f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/dispatches"
        self.api.data[key]=TimeoutError("private raw response")
        with self.assertRaises(TimeoutError): self.dispatch()
        with self.assertRaisesRegex(mod.Blocked,"unresolved_no_retry"): self.dispatch()
        self.assertEqual(1,self.api.posts)
    def test_intent_write_failure_prevents_post(self):
        with patch.object(receipts,"write_atomic",side_effect=OSError("denied")):
            with self.assertRaises(OSError): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_invalid_dispatch_response_does_not_retry(self):
        key=f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/dispatches"
        self.api.data[key]={"workflow_run_id":True}
        with self.assertRaisesRegex(mod.Blocked,"receipt_invalid_no_retry"): self.dispatch()
        with self.assertRaisesRegex(mod.Blocked,"unresolved_no_retry"): self.dispatch()
        self.assertEqual(1,self.api.posts)
    def test_wrong_run_sha_never_qualifies(self):
        self.api.data[f"repos/{mod.REPOSITORY}/actions/runs/123"]["head_sha"]="b"*40
        with self.assertRaisesRegex(mod.Blocked,"readback_mismatch"): self.dispatch()
        with self.assertRaisesRegex(mod.Blocked,"readback_mismatch"): self.dispatch()
        self.assertEqual(1,self.api.posts)
    def test_lock_conflict_blocks(self):
        (self.root/"dispatch.lock").write_text("other owner")
        with self.assertRaisesRegex(mod.Blocked,"lock_held"): self.dispatch()
        self.assertEqual("other owner",(self.root/"dispatch.lock").read_text())
    def test_checkpoint_binding_prevents_duplicate_dispatch(self):
        (self.root/(CORR+".json")).write_text(json.dumps({"source_sha":"c"*40,"correlation_id":CORR}))
        with self.assertRaisesRegex(mod.Blocked,"checkpoint_binding"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_unknown_endpoint_blocked_before_process(self):
        client=object.__new__(mod.GitHubRead)
        with patch.object(mod.subprocess,"run") as call:
            with self.assertRaisesRegex(mod.Blocked,"endpoint_not_allowed"):
                client.call(f"repos/{mod.REPOSITORY}/actions/runners/1",post=True)
            call.assert_not_called()
    def test_expected_cli_headers_no_shell_no_secret_arguments(self):
        client=object.__new__(mod.GitHubRead)
        client.binary="gh-fixture"
        client.env={}
        with patch.object(mod.subprocess,"run",return_value=types.SimpleNamespace(
                returncode=0,stdout='{"login":"ericson-j-santos"}',stderr="")) as call:
            client.call("user")
            a,k=call.call_args
            self.assertIn("X-GitHub-Api-Version: 2026-03-10",a[0])
            self.assertFalse(k["shell"])
            self.assertEqual(35,k["timeout"])
    def test_cli_error_is_sanitized(self):
        client=object.__new__(mod.GitHubRead)
        client.binary="gh-fixture"; client.env={}
        with patch.object(mod.subprocess,"run",return_value=types.SimpleNamespace(
                returncode=1,stdout="",stderr="private-credential HTTP 403")):
            with self.assertRaisesRegex(mod.Blocked,"^github_http_403$"): client.call("user")
    def test_local_source_sha_guard_calls_existing_validator(self):
        with patch.object(mod.os,"name","nt"),patch.object(mod.socket,"gethostname",return_value="Noteri"),\
                patch.object(native,"source_head") as guard:
            mod.guard(SHA,CORR)
            guard.assert_called_once_with(SHA)
    def test_wrong_host_blocks_before_source_read(self):
        with patch.object(mod.socket,"gethostname",return_value="OtherHost"),patch.object(native,"source_head") as guard:
            with self.assertRaisesRegex(mod.Blocked,"noteri_required"): mod.guard(SHA,CORR)
            guard.assert_not_called()

    def test_invalid_correlation_blocks_before_journal(self):
        with self.assertRaisesRegex(mod.Blocked,"correlation_invalid"):
            mod.dispatch_once(self.api,SHA,"../../other",self.root,mod.CONFIRM)
        self.assertEqual([],list(self.root.iterdir()))
    def test_incomplete_runs_do_not_allow_ambiguous_queue(self):
        self.api.data[f"repos/{mod.REPOSITORY}/actions/workflows/{mod.WORKFLOW}/runs?per_page=100"]={
            "total_count":101,"workflow_runs":[]}
        with self.assertRaisesRegex(mod.Blocked,"runs_incomplete"): self.dispatch()
        self.assertEqual(0,self.api.posts)
    def test_replay_does_not_export_extra_local_fields(self):
        self.dispatch()
        p=self.root/(CORR+".json")
        old=json.loads(p.read_text()); old["private"]="must-not-export"
        p.write_text(json.dumps(old))
        self.assertNotIn("must-not-export",json.dumps(self.dispatch()))
    def test_false_qualification_claim_in_checkpoint_blocks(self):
        self.dispatch()
        p=self.root/(CORR+".json")
        old=json.loads(p.read_text()); old["hml_verified"]=True
        p.write_text(json.dumps(old))
        with self.assertRaisesRegex(mod.Blocked,"checkpoint_shape"): self.dispatch()
        self.assertEqual(1,self.api.posts)

if __name__=="__main__": unittest.main()
