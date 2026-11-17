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
            self.assertEqual(set(self.doc['jobs']), {'contract', 'physical'})
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
        self.assertIn('APPROVED_INGEST_BLOB: 0cdeed7cf94ab187157b44b43cc2bc2d11221cc1', t)
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
        self.assertNotIn("'--confirm'", t)

    def test_no_binary_transfer_secret_or_deployment(self):
        t = self.raw
        self.assertNotIn('secrets.', t)
        self.assertNotIn('upload-artifact', t)
        self.assertNotIn('download-artifact', t)
        self.assertNotIn('docker', t.lower())
        self.assertNotIn('powershell -command', t.lower())
        self.assertNotIn('git push', t)
        self.assertNotIn('gh api', t)
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
            self.assertEqual(self.doc['permissions'], {'contents': 'read'})


if __name__ == '__main__':
    unittest.main()
