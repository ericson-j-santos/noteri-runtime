"""The legacy confirmation is enforced, not merely present in a comment."""
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_qualification_entrypoint as q

class ConfirmationTests(unittest.TestCase):
    def test_absent_or_wrong_confirmation_never_bootstraps(self):
        base = ["qualification", "--rules-root", ".", "--rules-sha", "a" * 40]
        for suffix in ([], ["--confirm", "WRONG"]):
            with self.subTest(suffix=suffix), patch.object(sys, "argv", base + suffix):
                with patch.object(q.pipeline, "launch") as launch, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(2, q.main())
                launch.assert_not_called()

    def test_exact_confirmation_calls_governed_launcher(self):
        args = ["qualification", "--rules-root", ".", "--rules-sha", "a" * 40,
                "--confirm", "PROBE-NOTERI-CONTROL-PLANE"]
        with patch.object(sys, "argv", args), patch.object(q.pipeline, "launch", return_value=0) as launch:
            self.assertEqual(0, q.main())
        launch.assert_called_once_with(Path("."), "a" * 40)

if __name__ == "__main__":
    unittest.main()


class WorkflowPinTests(unittest.TestCase):
    def test_probe_pins_canonical_rules_main_and_not_old_candidate(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "noteri-control-plane-probe.yml").read_text(encoding="utf-8")
        self.assertIn("RULES_SHA: 259b51d076939033cc9060a7d24ae352e10fe6a6", workflow)
        self.assertNotIn("515b52b2ec51aa60f02265bd5a1e6df057140ece", workflow)
