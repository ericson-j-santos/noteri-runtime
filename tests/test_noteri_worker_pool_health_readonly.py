"""Contract tests only; never claim these as a Noteri physical receipt."""
from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from scripts import noteri_worker_pool_health_readonly as gate


def env():
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": gate.REPOSITORY,
        "RUNNER_NAME": "Noteri-runtime", "GITHUB_SHA": "a" * 40,
        "SESSION_LAUNCH_RESULT": "SESSION_LAUNCH_OK",
        "SESSION_STATE_VALIDATED": "true", "SESSION_GATEWAY_BOUND": "true",
        "SESSION_SNAPSHOT_SHA256": "b" * 64,
    }


def body():
    return {"status": "not_ready", "storage_backend": "sqlite",
            "fenced_cutover_enabled": False, "auth_configured": True,
            "authority_id": None, "secret": "never-print"}


class FakeResponse:
    status = 503
    def geturl(self):
        return gate.URL
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, count):
        assert count == 8193
        return json.dumps(body()).encode()


class Risk1Tests(unittest.TestCase):
    def test_valid_context(self):
        gate.authorize(env(), "Noteri", "nt")

    def test_host_runner_and_session_fail_closed(self):
        with self.assertRaises(gate.Blocked):
            gate.authorize(env(), "Other", "nt")
        for key, value in (("GITHUB_SHA", "bad"), ("RUNNER_NAME", "other"),
                           ("SESSION_STATE_VALIDATED", "false"),
                           ("SESSION_SNAPSHOT_SHA256", "")):
            with self.subTest(key=key), self.assertRaises(gate.Blocked):
                gate.authorize({**env(), key: value}, "Noteri", "nt")

    def test_exact_loopback_get(self):
        class Client:
            def open(self, req, timeout):
                self.args = req.full_url, req.get_method(), timeout
                return FakeResponse()
        client = Client()
        code, payload = gate.read_health(client)
        self.assertEqual((code, payload), (503, body()))
        self.assertEqual(client.args, (gate.URL, "GET", 3))

    def test_redirect_rejected(self):
        class Redirect(FakeResponse):
            def geturl(self):
                return "https://example.invalid"
        class Client:
            def open(self, *_a, **_kw):
                return Redirect()
        with self.assertRaises(gate.Blocked):
            gate.read_health(Client())

    def test_staged_is_not_active_release_and_secret_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ReqSys" / "NoteriWorkerPool" / "releases" /
             ("c" * 40)).mkdir(parents=True)
            result = gate.sanitize(503, body(), gate.staged_releases(tmp))
            self.assertIsNone(result["active_release_sha"])
            self.assertFalse(result["ready_for_builder"])
            self.assertFalse(result["cost_zero_attested"])
            self.assertNotIn("never-print", json.dumps(result))

    def test_invalid_release_entry_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ReqSys" / "NoteriWorkerPool" / "releases" /
             "wrong").mkdir(parents=True)
            with self.assertRaises(gate.Blocked):
                gate.staged_releases(tmp)

    def test_invalid_health_field_blocked(self):
        for change in ({"fenced_cutover_enabled": "true"},
                       {"authority_id": "token"}, {"storage_backend": "bad"}):
            with self.subTest(change=change), self.assertRaises(gate.Blocked):
                gate.sanitize(200, {**body(), **change}, [])

    def test_no_control_plane_mutators(self):
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "schtasks.exe", "/v1/claims",
                          "/api/chat", "Authorization", "method=\"POST\""):
            self.assertNotIn(forbidden, source)
        self.assertIn("ProxyHandler({})", source)
        self.assertIn("NoRedirect()", source)


if __name__ == "__main__":
    unittest.main()
