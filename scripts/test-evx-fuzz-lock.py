#!/usr/bin/env python3
"""Fixture checks for shared shipping/fuzz package identity alignment."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("fuzz_lock", Path(__file__).with_name("check-evx-fuzz-lock.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class FuzzLockTests(unittest.TestCase):
    def setUp(self):
        self.package = {"name": "engine", "version": "1.2.3", "source": "registry+https://example.invalid/index", "checksum": "a" * 64}
        self.application = {"package": [deepcopy(self.package)]}

    def test_identical_shared_identity_is_accepted(self):
        self.assertEqual(checker.mismatches(self.application, deepcopy(self.application)), [])

    def test_version_source_and_checksum_drift_are_each_rejected(self):
        for key, value in [("version", "1.2.4"), ("source", "registry+https://elsewhere.invalid/index"), ("checksum", "b" * 64)]:
            with self.subTest(field=key):
                changed = deepcopy(self.package)
                changed[key] = value
                self.assertEqual(checker.mismatches(self.application, {"package": [changed]}), [f"engine {changed['version']}"])

    def test_missing_registry_source_or_checksum_is_rejected(self):
        for key in ["source", "checksum"]:
            with self.subTest(field=key):
                changed = deepcopy(self.package)
                del changed[key]
                self.assertEqual(checker.mismatches(self.application, {"package": [changed]}), ["engine 1.2.3"])

    def test_path_packages_match_without_registry_metadata(self):
        shipping = {"package": [{"name": "evx-api", "version": "0.1.0"}]}
        self.assertEqual(checker.mismatches(shipping, deepcopy(shipping)), [])
        self.assertEqual(checker.mismatches(shipping, {"package": [{"name": "evx-api", "version": "0.2.0"}]}), ["evx-api 0.2.0"])

    def test_fuzz_only_tooling_and_shipping_only_packages_are_allowed(self):
        fuzz = {"package": [deepcopy(self.package), {"name": "libfuzzer-sys", "version": "0.4.99", "source": "registry+https://example.invalid/index", "checksum": "c" * 64}]}
        self.application["package"].append({"name": "desktop-shell", "version": "0.1.0"})
        self.assertEqual(checker.mismatches(self.application, fuzz), [])

    def test_each_of_multiple_shipping_versions_is_allowed_but_another_is_not(self):
        other = deepcopy(self.package)
        other.update(version="2.0.0", checksum="d" * 64)
        self.application["package"].append(other)
        self.assertEqual(checker.mismatches(self.application, deepcopy(self.application)), [])
        changed = deepcopy(other)
        changed["version"] = "2.0.1"
        self.assertEqual(checker.mismatches(self.application, {"package": [changed]}), ["engine 2.0.1"])

    def test_cli_reads_both_lockfiles_and_returns_failure_for_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz").mkdir()
            lock = 'version = 4\n[[package]]\nname = "evx-api"\nversion = "0.1.0"\n'
            (root / "Cargo.lock").write_text(lock)
            (root / "fuzz/Cargo.lock").write_text(lock)
            with patch.object(checker, "__file__", str(root / "scripts/check-evx-fuzz-lock.py")):
                output, error = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(error):
                    self.assertEqual(checker.main(), 0)
                self.assertIn("match shipping", output.getvalue())
                self.assertEqual(error.getvalue(), "")
                (root / "fuzz/Cargo.lock").write_text(lock.replace("0.1.0", "0.2.0"))
                output, error = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(error):
                    self.assertEqual(checker.main(), 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("evx-api 0.2.0", error.getvalue())


if __name__ == "__main__":
    unittest.main()
