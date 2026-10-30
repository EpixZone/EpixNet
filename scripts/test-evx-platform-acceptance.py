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

    def test_a_stalled_or_failed_version_probe_is_recorded_not_fatal(self):
        stalled = acceptance.tool_version([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
        self.assertTrue(stalled.startswith("unavailable: TimeoutExpired"), stalled)
        failed = acceptance.tool_version([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertTrue(failed.startswith("unavailable: CalledProcessError"), failed)
        missing = acceptance.tool_version(["evx-no-such-tool-for-this-test"])
        self.assertTrue(missing.startswith("unavailable: FileNotFoundError"), missing)
        self.assertEqual(acceptance.tool_version([sys.executable, "-c", "print('v1')"]), "v1")

    def test_windows_core_profile_does_not_claim_native_worker_acceptance(self):
        all_args = [arg for _, command in acceptance.commands("windows-core") for arg in command]
        self.assertNotIn("evx-worker", all_args)
        self.assertNotIn("evx-supervisor", all_args)
        self.assertIn("windows-browser", all_args)

    def test_windows_profile_runs_the_native_suites_fixtures_and_worker_checks(self):
        names = [name for name, _ in acceptance.commands("windows", Path("evidence"))]
        self.assertEqual(names, ["native", "native-primitives", "fixture-build", "isolation", "execution",
                                 "worker-build", "worker-copy", "worker", "product-gates", "package"])
        all_args = [arg for _, command in acceptance.commands("windows", Path("evidence")) for arg in command]
        self.assertIn("evx-worker", all_args)
        self.assertIn("evx-supervisor", all_args)
        self.assertIn("epix-evx", all_args)
        self.assertTrue(any(arg.endswith("acceptance.exe") for arg in all_args))


if __name__ == "__main__":
    unittest.main()
