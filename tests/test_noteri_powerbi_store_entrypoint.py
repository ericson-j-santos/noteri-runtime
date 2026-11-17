"""Contract controls for narrowly-scoped Noteri physical identity entrypoint."""
from __future__ import annotations

import pathlib
import unittest

try:
    import yaml
except ImportError:
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/noteri-powerbi-store-identity-preflight.yml'


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text(encoding='utf-8')
        if yaml is not None:
            cls.doc = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        else:
            cls.doc = None

    def test_workflow_has_one_typed_physical_entrypoint(self):
        self.assertIn('  physical:', self.raw)
        self.assertIn('  contract:', self.raw)
        self.assertIn('runs-on: [self-hosted, Windows, X64, noteri, reqsys-dev]', self.raw)
        self.assertIn('  push:', self.raw)
        self.assertIn('  pull_request:', self.raw)
        self.assertNotIn('  schedule:', self.raw)
        self.assertNotIn('  workflow_dispatch:', self.raw)
        if self.doc is not None:
            self.assertEqual(set(self.doc['jobs']), {'contract', 'physical', 'observe_push'})
            self.assertEqual(self.doc['jobs']['physical']['runs-on'],
                             ['self-hosted', 'Windows', 'X64', 'noteri', 'reqsys-dev'])

    def test_physical_never_runs_for_pull_request(self):
        t = self.raw
        self.assertIn("github.event_name == 'push'", t)
        self.assertIn("github.actor == 'ericson-j-santos'", t)
        self.assertIn('needs.contract.result == \'success\'', t)
        self.assertIn("github.ref == 'refs/heads/feature/noteri-private-powerbi-store-ingest-issue92'", t)
        self.assertIn('cancel-in-progress: false', t)
        self.assertIn('noteri-store-identity-physical', t)

    def test_sources_are_pinned_and_checkout_does_not_leave_credentials(self):
        t = self.raw
        self.assertEqual(t.count('actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09'), 3)
        self.assertEqual(t.count('persist-credentials: false'), 3)
        self.assertIn('58dcd4200f412a866278027ba9e433439a03f3b3', t)
        self.assertIn('APPROVED_INGEST_BLOB: 6d62866951c044c16ca0bc2ef03c05f871fa4021', t)
        self.assertIn('git hash-object scripts/noteri_powerbi_store_ingest.py', t)
        self.assertIn('--expected-head', t)
        self.assertIn('origin/feature/noteri-private-powerbi-store-ingest-issue92', t)

    def test_gateway_is_required_to_execute_and_receipt_nonpromoting(self):
        t = self.raw
        self.assertIn('scripts/session_launcher.py', t)
        self.assertIn("$session.result -ne 'SESSION_LAUNCH_OK'", t)
        self.assertIn('$session.state_validated -ne $true', t)
        self.assertIn('--require-runner-version-preflight', t)
        self.assertIn('scripts/command_gateway.py', t)
        self.assertIn("'--risk', '1'", t)
        self.assertIn('--preflight-only', t)
        self.assertIn('$report.mutations_performed -ne $false', t)
        self.assertIn('$report.transport_ready -ne $false', t)
        self.assertIn("NOTERI_STORE_PREFLIGHT_BLOCKED=$($report.reason)", t)
        self.assertIn('SOURCE_CONFIG_MISSING', t)
        self.assertIn('SOURCE_CONFIG_ACCESS_DENIED', t)
        self.assertNotIn("'--confirm'", t)

    def test_no_binary_transfer_secret_or_deployment(self):
        t = self.raw
        self.assertNotIn('secrets.', t)
        self.assertNotIn('upload-artifact', t)
        self.assertNotIn('download-artifact', t)
        self.assertNotIn('docker', t.lower())
        self.assertNotIn('powershell -command', t.lower())
        self.assertNotIn('git push', t)
        self.assertNotIn('gh api', t.split('\n  physical:', 1)[1].split('\n  observe_push:', 1)[0])
        self.assertNotIn('INGEST-POWERBI-STORE-NOTERI-DEV', t)

    def test_no_dynamic_path_command_or_url_inputs(self):
        self.assertIn('runs-on: ubuntu-24.04', self.raw)
        self.assertIn('  contents: read', self.raw)
        self.assertIn('timeout-minutes: 8', self.raw)
        self.assertIn('--preflight-only', self.raw)
        self.assertNotIn('inputs.', self.raw)
        if self.doc is not None:
            jobs = self.doc['jobs']
            self.assertEqual(jobs['contract']['runs-on'], 'ubuntu-24.04')
            self.assertEqual(self.doc['permissions'], {'contents': 'read', 'actions': 'read'})


    def test_push_observer_has_no_physical_or_mutation_route(self):
        raw = self.raw.split('\n  observe_push:', 1)[1]
        self.assertIn("github.event_name == 'pull_request'", raw)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", raw)
        self.assertIn("github.event.pull_request.user.login == 'ericson-j-santos'", raw)
        self.assertIn('runs-on: ubuntu-24.04', raw)
        self.assertIn('GH_TOKEN: ${{ github.token }}', raw)
        self.assertIn('gh api -X GET', raw)
        self.assertIn('head_sha=${SOURCE_SHA}&per_page=100', raw)
        self.assertIn('.event == "push"', raw)
        self.assertIn('.head_sha == $sha', raw)
        self.assertIn('NO_MATCHING_PUSH_RUN', raw)
        self.assertIn('physical_effect_verified:false', raw)
        self.assertIn('credentials_checked:false', raw)
        self.assertNotIn('workflow_dispatch', raw)
        self.assertNotIn('rerun', raw.lower())
        self.assertNotIn('gh api -X POST', raw)
        self.assertNotIn('set-secret', raw)
        self.assertNotIn('download-artifact', raw)
        if self.doc is not None:
            self.assertEqual(self.doc['jobs']['observe_push']['runs-on'], 'ubuntu-24.04')

    def test_push_observer_does_not_promote_absent_run_as_host_success(self):
        from subprocess import run
        import json
        sample = {'workflow_runs': [
          {'id': 2, 'head_sha': 'a'*40, 'event': 'pull_request', 'name': 'Noteri STORE - Identity Preflight (read only)', 'run_number': 2},
          {'id': 3, 'head_sha': 'b'*40, 'event': 'push', 'name': 'Noteri STORE - Identity Preflight (read only)', 'run_number': 3},
          {'id': 4, 'head_sha': 'a'*40, 'event': 'push', 'name': 'unrelated', 'run_number': 4},
          {'id': 5, 'head_sha': 'a'*40, 'event': 'push', 'name': 'Noteri STORE - Identity Preflight (read only)', 'run_number': 5},
        ]}
        jq_expression = '([.workflow_runs[]? | select(.head_sha == $sha and .event == "push" and .name == "Noteri STORE - Identity Preflight (read only)")] | sort_by(.run_number) | last) // null'
        import shutil
        if not shutil.which('jq'):
            self.skipTest('jq indisponivel no ambiente local; CI GitHub Ubuntu possui jq')
        good = run(['jq','-c','--arg','sha','a'*40,jq_expression],input=json.dumps(sample),text=True,capture_output=True,check=True)
        self.assertEqual(json.loads(good.stdout)['id'],5)
        absent = run(['jq','-c','--arg','sha','c'*40,jq_expression],input=json.dumps(sample),text=True,capture_output=True,check=True)
        self.assertIsNone(json.loads(absent.stdout))


if __name__ == '__main__':
    unittest.main()
