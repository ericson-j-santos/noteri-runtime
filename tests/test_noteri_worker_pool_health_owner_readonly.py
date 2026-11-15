"""Fixed 8097 read-only HTTP/TCP probe, positive and negative controls."""
from __future__ import annotations

import json
import socket
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_worker_pool_health_owner_readonly as probe


class Reply:
    status = 200
    def __init__(self, data): self.data=json.dumps(data).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, limit): return self.data[:limit]


class ProbeTests(unittest.TestCase):
    def test_port_8097_parser_identifies_pid(self):
        payload=struct.pack("<I",1)+struct.pack("<6I",2,0,socket.htons(8097),0,0,1234)
        self.assertEqual(probe.port_owner_pids(payload),[1234])

    def test_wrong_port_is_not_accepted(self):
        payload=struct.pack("<I",1)+struct.pack("<6I",2,0,socket.htons(11434),0,0,1234)
        self.assertEqual(probe.port_owner_pids(payload),[])

    def test_truncated_table_rejected(self):
        with self.assertRaises(probe.Blocked):
            probe.port_owner_pids(struct.pack("<I",999999))

    def test_health_accepts_only_expected_service(self):
        data={"service":"codex-worker-pool", "status":"healthy",
              "auth_configured":True,
              "expected_rules_sha_configured":True,
              "storage_backend":"sqlite","contract_version":"1"}
        with patch.object(probe.urllib.request, "build_opener") as op:
            op.return_value.open.return_value=Reply(data)
            result=probe.probe_health()
        self.assertEqual(result["result"],"WORKER_POOL_API_HEALTHY")
        self.assertNotIn("authority_id",result)
        self.assertEqual(result["http_status"],200)

    def test_shared_authority_and_fencing_are_independent_of_http_healthy(self):
        data = {"service":"codex-worker-pool", "status":"healthy",
                "auth_configured":True,"expected_rules_sha_configured":True,
                "authority_id":None, "fenced_cutover_enabled":False,
                "storage_backend":"sqlite"}
        with patch.object(probe.urllib.request, "build_opener") as op:
            op.return_value.open.return_value=Reply(data)
            result=probe.probe_health()
        self.assertEqual(result["result"], "WORKER_POOL_API_HEALTHY")
        self.assertFalse(result["authority_id_present"])
        self.assertFalse(result["fenced_cutover_enabled"])
        data.update(authority_id="opaque-private-id", fenced_cutover_enabled=True)
        with patch.object(probe.urllib.request, "build_opener") as op:
            op.return_value.open.return_value=Reply(data)
            result=probe.probe_health()
        self.assertTrue(result["authority_id_present"])
        self.assertTrue(result["fenced_cutover_enabled"])
        self.assertNotIn("opaque-private-id", json.dumps(result))

    def test_other_service_is_not_attested(self):
        data={"service":"other","status":"healthy",
              "auth_configured":True,"expected_rules_sha_configured":True}
        with patch.object(probe.urllib.request, "build_opener") as op:
            op.return_value.open.return_value=Reply(data)
            self.assertEqual(probe.probe_health()["result"],"UNRECOGNIZED_SERVICE")

    def test_no_mutating_endpoints_or_credentials(self):
        body=(Path(__file__).resolve().parents[1] / "scripts"
              / "noteri_worker_pool_health_owner_readonly.py").read_text("utf-8")
        self.assertIn('http://127.0.0.1:8097/health',body)
        self.assertIn('method="GET"',body)
        for term in ('method="POST"', 'Authorization":', "Popen(",
                     "os.system(", "kill(", "terminate("):
            self.assertNotIn(term,body)


if __name__ == "__main__":
    unittest.main()
