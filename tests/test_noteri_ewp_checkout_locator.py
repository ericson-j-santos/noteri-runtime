"""Testes do localizador Worker Pool: read-only, fail-closed, sem fallback."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

SRC=Path(__file__).resolve().parents[1]/"scripts"/"noteri_ewp_checkout_locator.py"
spec=importlib.util.spec_from_file_location("ewp_locator",SRC)
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)

class LocatorTests(unittest.TestCase):
    def test_blocks_other_host(self):
        self.assertEqual(m.locate("Desktop","nt",m.CONFIRM,"e"*40,Path("missing"))["result"],
                         "EWP_LOCATOR_BLOCKED")

    def test_blocks_wrong_confirmation(self):
        self.assertEqual(m.locate("Noteri","nt","WRONG","e"*40,Path("missing"))["result"],
                         "EWP_LOCATOR_BLOCKED")

    def test_blocks_wrong_sha(self):
        self.assertEqual(m.locate("Noteri","nt",m.CONFIRM,"bad",Path("missing"))["result"],
                         "EWP_LOCATOR_BLOCKED")

    def test_no_checkout_not_reported_as_ready(self):
        with TemporaryDirectory() as tmp:
            with patch.object(m,"ROOT",Path(tmp)),patch.object(
                m,"git_text",return_value="e"*40
            ):
                out=m.locate("Noteri","nt",m.CONFIRM,"e"*40,Path(tmp))
            self.assertEqual(out["candidate_count"],0)
            self.assertFalse(out["state_changed"])

    def test_large_directory_with_no_matching_names_returns_empty(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            for i in range(301):
                (root/("other-"+str(i))).mkdir()
            with patch.object(m, "ROOT", root), patch.object(
                m, "git_text", return_value="e"*40
            ):
                out=m.locate("Noteri","nt",m.CONFIRM,"e"*40,Path(tmp))
            self.assertEqual(out["candidate_count"],0)

    def test_wrong_remote_rejected(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/".git").mkdir()
            def run(_, *args):
                if args==("rev-parse","--show-toplevel"): return str(root)
                if args==("rev-parse","HEAD"): return "e"*40
                if args==("config","--get","remote.origin.url"):
                    return "https://github.com/else/other.git"
                return ""
            with patch.object(m,"git_text",side_effect=run):
                self.assertIsNone(m.candidate(root))

    def test_accept_exact_remote_without_exposing_secret(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/".git").mkdir()
            def run(_, *args):
                if args==("rev-parse","--show-toplevel"): return str(root)
                if args==("rev-parse","HEAD"): return "e"*40
                if args==("config","--get","remote.origin.url"):
                    return "https://example-secret@github.com/ericson-j-santos/engineering-worker-pool.git"
                if args==("status","--porcelain","--untracked-files=no"): return ""
                return None
            with patch.object(m,"git_text",side_effect=run):
                result=m.candidate(root)
            self.assertIsNotNone(result)
            self.assertNotIn("example-secret",str(result))

    def test_source_does_not_write_or_execute_remote_scripts(self):
        src=SRC.read_text("utf-8")
        for x in ("Popen(", "shell=True", "git clone", "git fetch", "mkdir(", "write_text(", "os.system("):
            self.assertNotIn(x,src)

if __name__=="__main__":
    unittest.main()
