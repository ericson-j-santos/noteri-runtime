"""Canonical WSL opt-in normalization, without altering installed policy."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_gateway_update_profile_readonly as p

class ProfileNormalizationTests(unittest.TestCase):
    def test_omitted_wsl_flag_is_disabled(self):
        self.assertIs(p.validated_wsl_profile({"rules_version":"1.6.20"}), False)

    def test_explicit_disabled_is_disabled(self):
        self.assertIs(p.validated_wsl_profile({"noteri_wsl_running_inventory":False}), False)

    def test_explicit_enabled_is_preserved(self):
        self.assertIs(p.validated_wsl_profile({"noteri_wsl_running_inventory":True}), True)

    def test_null_and_nonboolean_are_denied(self):
        for val in (None, 0, 1, "false", [], {}):
            with self.subTest(value=val):
                with self.assertRaisesRegex(p.Blocked, "WSL_PROFILE_NOT_BOOLEAN"):
                    p.validated_wsl_profile({"noteri_wsl_running_inventory":val})

    def test_policy_must_be_object(self):
        with self.assertRaisesRegex(p.Blocked, "INSTALLED_POLICY_NOT_OBJECT"):
            p.validated_wsl_profile(None)

if __name__=="__main__":
    unittest.main()
