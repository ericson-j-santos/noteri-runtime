"""Bounded tests of the Noteri Git-state stderr diagnostic (no live Git)."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import noteri_git_gateway_stderr_diagnostic as probe


class GitStateDiagnosticTests(unittest.TestCase):
    def test_fixed_commands_are_read_only(self):
        self.assertEqual(len(probe.COMMANDS), 7)
        self.assertTrue(all(command[0] == "git" for _, command in probe.COMMANDS))
        self.assertEqual(len(probe.TARGETS), 2)
        self.assertTrue(all("wt-chat-noteri-six-pspath" in p for p in probe.TARGETS))

    def test_classification_redacts_paths(self):
        for message, code in (
            ("warning: unsafe private-data C:/user", "warning_other"),
            ("fatal: detected dubious ownership in /secret", "ownership"),
            ("error: Permission denied at C:/private", "access_denied"),
            ("warning: fsmonitor /some/private/path", "fsmonitor"),
            ("fatal: unrecognized /secret", "fatal_other"),
        ):
            with self.subTest(code=code):
                actual = probe.classify_stderr(message)
                self.assertEqual(actual, code)
                self.assertNotIn("private", actual)
                self.assertNotIn("secret", actual)

    def test_first_stderr_command_detected_without_raw_log(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            successes = [
                SimpleNamespace(returncode=0, stdout=str(root), stderr=""),
                SimpleNamespace(returncode=0, stdout=probe.EXPECTED_HEAD, stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr="warning: /secret"),
            ]
            with patch.object(probe.subprocess, "run", side_effect=successes) as called:
                report = probe.probe(root, probe.EXPECTED_HEAD)
            self.assertEqual(report["first_blocked"], "current_branch")
            self.assertEqual(len(report["steps"]), 3)
            self.assertEqual(report["steps"][-1]["stderr_type"], "warning_other")
            self.assertNotIn("/secret", str(report))
            self.assertEqual(called.call_count, 3)
            self.assertTrue(all(call.kwargs["shell"] is False
                                for call in called.call_args_list))

    def test_refuses_wrong_head_and_invalid_target(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaisesRegex(probe.Blocked, "HEAD_INVALID"):
                probe.probe(root, "invalid")
            with self.assertRaisesRegex(probe.Blocked, "WORKTREE_UNAVAILABLE"):
                probe.probe(root / "missing", probe.EXPECTED_HEAD)


    def test_git_warning_details_redact_path(self):
        payload = "warning: could not open directory 'C:/private/name': Permission denied"
        details = probe.error_details(payload)
        self.assertEqual(details["message_code"], "unreadable_directory")
        self.assertTrue(details["permission_denied"])
        self.assertTrue(details["has_quoted_target"])
        self.assertTrue(details["has_warning_prefix"])
        self.assertNotIn("private", str(details))
        self.assertEqual(probe.error_details("")["message_code"], "UNCLASSIFIED")

    def test_directory_warning_names_are_bounded(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for value, expected, reason in (
                ("tmp/", "tmp", "NOT_FOUND"),
                ("private_project/", "OTHER_RELATIVE", "ACCESS_DENIED"),
            ):
                suffix = ("No such file or directory" if reason == "NOT_FOUND"
                          else "Permission denied")
                warning = f"warning: could not open directory '{value}': {suffix}"
                detail = probe.directory_warning_details(warning, root)
                self.assertEqual(detail["directory_class"], expected)
                self.assertEqual(detail["reason"], reason)
                self.assertNotIn("private_project", str(detail))
                self.assertFalse(detail["directory_present"])
            self.assertEqual(
                probe.directory_warning_details(
                    "warning: could not open directory '../secret': inaccessible", root
                )["directory_class"],
                "REDACTED",
            )

    def test_warning_directory_shape_has_no_path_leak(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            data = probe.directory_warning_details(
                "warning: could not open directory 'example/': No such file or directory",
                root,
            )
            self.assertEqual(data["path_segments"], 1)
            self.assertEqual(data["target_length"], 8)
            self.assertEqual(data["name_length"], 7)
            self.assertTrue(data["target_ascii"])
            self.assertTrue(data["parent_present"])
            self.assertFalse(data["parent_has_exact_entry"])
            self.assertFalse(data["directory_present"])
            self.assertNotIn("example/", str(data))
            reserved = probe.directory_warning_details(
                "warning: could not open directory 'nul/': No such file or directory",
                root,
            )
            self.assertTrue(reserved["windows_reserved_name"])

    def test_raw_warning_byte_decoding_matches_actual_directory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            target = root / "café"
            target.mkdir()
            message = "warning: could not open directory 'café/': No such file or directory\n"
            raw = message.encode("cp1252")
            with patch.object(
                probe.subprocess, "run",
                return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=raw),
            ) as git:
                result = probe.raw_directory_identity(root)
            self.assertEqual(result["status"], "DIRECTORY_WARNING_CROSSCHECKED")
            cp1252 = [x for x in result["candidate_decodings"]
                      if x["encoding"] == "cp1252"]
            self.assertEqual(len(cp1252), 1)
            self.assertTrue(cp1252[0]["exact_entry"])
            self.assertTrue(cp1252[0]["is_dir"])
            self.assertNotIn("café", str(result))
            self.assertNotIn("caf", str(result))
            self.assertIs(git.call_args.kwargs["text"], False)
            self.assertIs(git.call_args.kwargs["shell"], False)

    def test_unicode_normalization_matches_without_escaping_name(self):
        import unicodedata
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            folded_name = unicodedata.normalize("NFD", "café")
            (root / folded_name).mkdir()
            raw = "warning: could not open directory 'café/': No such file or directory".encode("utf-8")
            with patch.object(
                probe.subprocess, "run",
                return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=raw),
            ):
                data = probe.raw_directory_identity(root)
            utf8 = [x for x in data["candidate_decodings"] if x["encoding"] == "utf-8"][0]
            self.assertTrue(utf8["normalized_nfc_match"])
            self.assertNotIn("café", str(data))
            self.assertEqual(utf8["replacement_character_count"], 0)

    def test_raw_git_warning_absent_is_not_reported_as_fixed(self):
        with tempfile.TemporaryDirectory() as t:
            with patch.object(
                probe.subprocess, "run",
                return_value=SimpleNamespace(
                    returncode=0, stdout=b"", stderr=b"",
                ),
            ):
                result = probe.raw_directory_identity(Path(t))
            self.assertEqual(result["status"], "NO_DIRECTORY_WARNING")

    def test_fixed_areas_do_not_emit_raw_git_stderr(self):
        with tempfile.TemporaryDirectory() as t:
            secret = "warning: could not open directory 'C:/private': Permission denied"
            answers = [
                SimpleNamespace(returncode=0, stdout="", stderr=secret)
                for _ in range(5)
            ]
            with patch.object(probe.subprocess, "run", side_effect=answers) as called:
                result = probe.isolate_untracked_warning(Path(t))
            self.assertEqual(len(result), 5)
            self.assertTrue(all(x["stderr_code"] == "unreadable_directory" for x in result))
            self.assertNotIn("private", str(result))
            self.assertEqual([x["area"] for x in result], [
                ".github", ".sdd", "docs", "scripts", "tests",
            ])
            self.assertTrue(all(call.kwargs["shell"] is False for call in called.call_args_list))

    def test_git_option_profiles_are_fixed_and_do_not_leak_error(self):
        with tempfile.TemporaryDirectory() as t:
            raw = "warning: could not open directory 'private/': No such file or directory"
            fake = SimpleNamespace(returncode=0, stdout="", stderr=raw)
            with patch.object(probe.subprocess, "run", return_value=fake) as called:
                rows = probe.compare_readonly_git_options(Path(t))
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(r["stderr_code"] == "unreadable_directory" for r in rows))
            self.assertNotIn("private", str(rows))
            self.assertEqual(called.call_count, 3)
            for call in called.call_args_list:
                self.assertEqual(call.args[0][0], "git")
                self.assertEqual(call.args[0][-5:],
                                 ("ls-files", "--others", "--exclude-standard", "-z", "--", ".")[-5:])
                self.assertFalse(call.kwargs["shell"])

    def test_last_git_step_warning_is_not_reported_as_clean(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            checks = [
                SimpleNamespace(returncode=0, stdout=str(root), stderr=""),
                SimpleNamespace(returncode=0, stdout=probe.EXPECTED_HEAD, stderr=""),
            ] + [SimpleNamespace(returncode=0, stdout="", stderr="")
                 for _ in range(4)]
            checks.append(SimpleNamespace(returncode=0, stdout="",
                                          stderr="warning: private path unavailable"))
            with patch.object(probe.subprocess, "run", side_effect=checks):
                result = probe.probe(root, probe.EXPECTED_HEAD)
            self.assertEqual(len(result["steps"]), 7)
            self.assertEqual(result["status"], "GIT_STATE_COMMAND_BLOCKED")
            self.assertEqual(result["first_blocked"], "modified")
            self.assertNotIn("private", str(result))

    def test_clean_git_state_requires_all_seven_checks(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            answers = [
                SimpleNamespace(returncode=0, stdout=str(root), stderr=""),
                SimpleNamespace(returncode=0, stdout=probe.EXPECTED_HEAD, stderr=""),
            ] + [SimpleNamespace(returncode=0, stdout="", stderr="") for _ in range(5)]
            with patch.object(probe.subprocess, "run", side_effect=answers):
                report = probe.probe(root, probe.EXPECTED_HEAD)
            self.assertEqual(report["status"], "GIT_STATE_COMMANDS_CLEAN")
            self.assertIsNone(report["first_blocked"])
            self.assertEqual(len(report["steps"]), 7)


if __name__ == "__main__":
    unittest.main()
