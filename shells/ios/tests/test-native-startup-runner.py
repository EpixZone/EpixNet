#!/usr/bin/env python3
"""Check simulator selection and failure evidence without needing Xcode."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "startup_runner", Path(__file__).with_name("run-native-startup-ui.py"))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def runtime(version, available=True, family="iOS"):
    return {"identifier": f"com.apple.CoreSimulator.SimRuntime.{family}-{version.replace('.', '-')}",
            "version": version, "isAvailable": available}


class StartupRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def select(self, sdk, runtimes):
        inventory = {"runtimes": runtimes, "devicetypes": [
            {"name": "iPhone SE (3rd generation)", "identifier": "iphone-se"}]}
        calls = []

        def command(output, *args, **kwargs):
            calls.append(args)
            if args == ("xcrun", "--sdk", "iphonesimulator", "--show-sdk-version"):
                return sdk
            if args == ("xcrun", "simctl", "list", "--json"):
                return json.dumps(inventory)
            if args[:3] == ("xcrun", "simctl", "create"):
                return "fixture-device"
            self.fail(f"Unexpected command: {args}")

        with patch.object(runner, "command", side_effect=command):
            udid = runner.select_device(self.output)
        self.assertEqual(udid, "fixture-device")
        selected = json.loads((self.output / "simulator.json").read_text())
        self.assertEqual(calls[-1][-1], selected["runtime"]["identifier"])
        self.assertEqual(selected["sdk_version"], sdk)
        return selected["runtime"]

    def test_runner_uses_sdk_release_instead_of_newest_installed_runtime(self):
        selected = self.select("18.5", [runtime(v) for v in ("18.5", "18.6", "26.0.1", "26.1", "26.2")])
        self.assertEqual(selected["version"], "18.5")

    def test_runtime_patch_versions_can_differ_from_sdk(self):
        selected = self.select("26.0", [runtime("26.0"), runtime("26.0.1"), runtime("26.2")])
        self.assertEqual(selected["version"], "26.0.1")

    def test_missing_or_unavailable_matching_runtime_fails_before_creating_device(self):
        for runtimes in ([runtime("26.2")],
                         [runtime("18.5", available=False)],
                         [runtime("18.5", family="tvOS")]):
            with self.subTest(runtimes=runtimes):
                with self.assertRaisesRegex(RuntimeError, "matching SDK 18.5"):
                    self.select("18.5", runtimes)
                self.assertFalse((self.output / "simulator.json").exists())

    def test_timeout_keeps_command_and_partial_output_in_log(self):
        args = ("xcrun", "simctl", "install", "fixture-device", "Fixture.app")
        error = subprocess.TimeoutExpired(args, 120, output=b"install still pending\n")
        with patch.object(runner.subprocess, "run", side_effect=error):
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.command(self.output, *args)
        log = (self.output / "commands.log").read_text()
        self.assertIn("$ xcrun simctl install fixture-device Fixture.app", log)
        self.assertIn("install still pending", log)
        self.assertIn("Timed out after 120 seconds", log)

    def test_optional_timeout_returns_partial_output_and_keeps_evidence(self):
        args = ("xcrun", "simctl", "spawn", "fixture-device", "log", "show")
        error = subprocess.TimeoutExpired(args, 30, output=b"partial simulator log\n")
        with patch.object(runner.subprocess, "run", side_effect=error):
            partial = runner.command(self.output, *args, timeout=30, check=False)
        self.assertEqual(partial, "partial simulator log")
        log = (self.output / "commands.log").read_text()
        self.assertIn("partial simulator log", log)
        self.assertIn("Timed out after 30 seconds", log)

    def run_with_cleanup_timeouts(self, assertions_pass):
        container = self.output / "container"
        documents = container / "Documents"
        documents.mkdir(parents=True)
        for scenario in ("portrait", "landscape"):
            passed = assertions_pass or scenario == "landscape"
            result = {"scenario": scenario, "passed": passed,
                      "checks": [{"name": "startup progress is visible", "passed": passed}]}
            (documents / f"{scenario}.json").write_text(json.dumps(result))
        calls = []

        def execute(args, **kwargs):
            calls.append(args)
            if args[:3] in (("xcrun", "simctl", "spawn"),
                            ("xcrun", "simctl", "shutdown"),
                            ("xcrun", "simctl", "delete")):
                raise subprocess.TimeoutExpired(args, kwargs["timeout"], output="cleanup still pending\n")
            stdout = str(container) if args[:3] == ("xcrun", "simctl", "get_app_container") else ""
            return subprocess.CompletedProcess(args, 0, stdout=stdout)

        with patch.object(runner, "select_device", return_value="fixture-device"), \
                patch.object(runner.subprocess, "run", side_effect=execute):
            try:
                runner.run(self.output, self.output / "Fixture.app")
            finally:
                self.assertEqual([args[2] for args in calls[-3:]], ["spawn", "shutdown", "delete"])

    def test_cleanup_timeouts_do_not_fail_passing_native_assertions(self):
        self.run_with_cleanup_timeouts(assertions_pass=True)
        results = json.loads((self.output / "results.json").read_text())
        self.assertEqual([result["scenario"] for result in results], ["portrait", "landscape"])
        self.assertTrue(all(result["passed"] for result in results))
        self.assertEqual((self.output / "commands.log").read_text().count("Timed out after 30 seconds"), 3)

    def test_cleanup_timeouts_preserve_original_assertion_failure(self):
        with self.assertRaisesRegex(RuntimeError, "Native startup regressions:\\nstartup progress is visible"):
            self.run_with_cleanup_timeouts(assertions_pass=False)


if __name__ == "__main__":
    unittest.main()
