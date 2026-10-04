#!/usr/bin/env python3
"""Evidence runner checks using disposable, inert subprocesses."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).with_name("evx-platform-acceptance.py"))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class AcceptanceTests(unittest.TestCase):
    def test_failed_check_is_retained_and_later_checks_do_not_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            checks = [("failed", [sys.executable, "-c", "print('fixture failure'); raise SystemExit(7)"]),
                      ("unreached", [sys.executable, "-c", "raise SystemExit(0)"])]
            self.assertEqual(acceptance.run_checks(checks, root, output, {}, os.environ.copy()), 1)
            record = json.loads((output / "manifest.json").read_text())
            self.assertFalse(record["completed"])
            self.assertEqual(len(record["checks"]), 1)
            self.assertEqual(record["checks"][0]["exit_code"], 7)
            self.assertEqual(record["checks"][0]["log_sha256"], acceptance.sha256(output / "failed.log"))

    def test_success_records_counts_and_does_not_overwrite_prior_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            checks = [("passed", [sys.executable, "-c", "print('test result: ok. 2 passed; 0 failed; 1 ignored;')"])]
            self.assertEqual(acceptance.run_checks(checks, root, output, {}, os.environ.copy()), 0)
            record = json.loads((output / "manifest.json").read_text())
            self.assertTrue(record["completed"])
            self.assertEqual(record["checks"][0]["passed"], 2)
            self.assertEqual(record["checks"][0]["ignored"], 1)
            with self.assertRaises(FileExistsError):
                acceptance.run_checks(checks, root, output, {}, os.environ.copy())

    def test_timeout_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            with patch.object(acceptance.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1800)):
                self.assertEqual(acceptance.run_checks([("timeout", ["fixture"])], root, output, {}, os.environ.copy()), 1)
            record = json.loads((output / "manifest.json").read_text())
            self.assertFalse(record["completed"])
            self.assertIsNone(record["checks"][0]["exit_code"])

    def test_windows_profile_does_not_claim_native_worker_acceptance(self):
        all_args = [arg for _, command in acceptance.commands("windows-core") for arg in command]
        self.assertNotIn("evx-worker", all_args)
        self.assertNotIn("evx-supervisor", all_args)
        self.assertIn("windows-browser", all_args)


if __name__ == "__main__":
    unittest.main()
