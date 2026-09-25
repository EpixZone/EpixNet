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


if __name__ == "__main__":
    unittest.main()
