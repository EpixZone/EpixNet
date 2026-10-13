#!/usr/bin/env python3
"""Run the real Apple adapter in a disposable, signed development app bundle."""

import importlib.util
import hashlib
import json
import os
import pwd
import uuid
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
os.environ.setdefault("CARGO_TARGET_DIR", str(REPO / "target" / "apple-xpc"))
spec = importlib.util.spec_from_file_location("transport_fixture", SOURCE / "test-xpc.py")
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
HOST_ID = "org.epixnet.evx.backend.fixture.host." + uuid.uuid4().hex
WORKER_ID = "org.epixnet.evx.backend.fixture.worker"


@unittest.skipUnless(sys.platform == "darwin", "macOS XPC required")
class AppleBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        transport.run([
            "cargo", "build", "-p", "evx-worker", "-p", "evx-supervisor",
            "--features", "evx-worker/apple-xpc,evx-supervisor/apple-xpc",
            "--bins", "--example", "apple_xpc_host", "--locked",
        ], timeout=600)
        metadata = json.loads(transport.run(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
        binaries = Path(metadata["target_directory"]) / "debug"
        cls.temporary = tempfile.TemporaryDirectory(prefix="evx-apple-backend-")
        cls.root = Path(cls.temporary.name).resolve()
        cls.authority = Path(pwd.getpwuid(os.geteuid()).pw_dir) / "Library" / "Containers" / HOST_ID / "Data" / "Library" / "Application Support" / "EpixNet" / "EVXAuthority"
        cls.workspaces = cls.authority.parent / "DevelopmentFixtures" / uuid.uuid4().hex
        package_spec = importlib.util.spec_from_file_location("package_backend", SOURCE / "package_backend.py")
        package = importlib.util.module_from_spec(package_spec)
        package_spec.loader.exec_module(package)
        cls.app = cls.root / "GameFixture.app"
        checked = package.build(cls.app, binaries / "examples" / "apple_xpc_host", binaries / "evx-worker",
                                binaries / "evx-xpc-service", HOST_ID, slots=3)
        cls.host = cls.app / "Contents" / "MacOS" / "host"
        cls.manifest = checked["manifest"]
        cls.roles = []
        for role in ("guest", "compiler", "file"):
            binding = checked["manifest"]["slots"][0][role]
            cls.roles.extend([binding["service"], binding["requirement"]])
        # Negative admission driver is a separate test-only app, so the real
        # backend app remains exactly the package the verifier inspected.
        companion = cls.root / "AdmissionTests.app"
        macos = companion / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        cls.admission = macos / "admission"
        transport.run(["xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra", "-Werror",
                       "-mmacosx-version-min=12.0", str(SOURCE / "backend-admission.c"),
                       "-framework", "CoreFoundation", "-framework", "Security", "-o", str(cls.admission)])
        services = companion / "Contents" / "XPCServices"
        services.mkdir()
        guest_name = cls.roles[0] + ".xpc"
        shutil.copytree(cls.app / "Contents" / "XPCServices" / guest_name, services / guest_name)
        (companion / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": HOST_ID, "CFBundleExecutable": "admission", "CFBundlePackageType": "APPL", "CFBundleVersion": "1"}))
        transport.sign(companion, HOST_ID)

    @classmethod
    def tearDownClass(cls):
        transport.run([str(cls.host), "cleanup", str(cls.workspaces), *cls.roles, str(cls.authority)])
        # Only random, suite-owned service data is removed. Idle services
        # retire themselves; no PID-based signalling or OS metadata deletion.
        time.sleep(31)
        for slot in cls.manifest["slots"]:
            for role in ("guest", "compiler", "file"):
                leaf = Path(pwd.getpwuid(os.geteuid()).pw_dir) / "Library/Containers" / slot[role]["service"] / "Data/Library/Application Support/EpixNet/EVXWorkspace"
                if leaf.exists():
                    shutil.rmtree(leaf)
        cls.temporary.cleanup()

    def invoke(self, case):
        workspace = self.workspaces / case
        result = subprocess.run(
            [str(self.host), case, str(workspace), *self.roles, str(self.authority)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_successive_invocations_get_fresh_workers(self):
        self.assertEqual(self.invoke("repeat")["value"], 42)

    def test_compile_and_execute_pulley_game(self):
        self.assertEqual(self.invoke("calculate")["value"], 42)

    def test_invalid_authority_records_and_descriptors_are_denied(self):
        for mode in ("read-write", "malformed", "wrong-mode", "hardlink", "replay", "same-connection"):
            with self.subTest(mode=mode):
                self.assertEqual(transport.run([str(self.admission), mode, *self.roles[:2], str(self.authority)]),
                                 "admission-denied\n")
        alternate = self.root / "untrusted-authority"
        alternate.mkdir(mode=0o700)
        self.assertEqual(transport.run([str(self.admission), "replaced-path", *self.roles[:2], str(alternate)]),
                         "admission-denied\n")
        self.assertEqual(list(self.authority.iterdir()), [])

    def test_file_service_roundtrip(self):
        self.invoke("file-roundtrip")

    def test_cross_slot_workspace_and_config_binding(self):
        self.invoke("cross-slot")

    def test_uncertain_write_recovers_only_after_trusted_reap(self):
        self.invoke("uncertain-recovery")

    def test_crashed_host_preserves_durable_process_quarantine(self):
        result = subprocess.run(
            [str(self.host), "crash-start", str(self.workspaces / "crash-start"), *self.roles, str(self.authority)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertTrue(self.invoke("crash-reopen")["quarantined"])

    def test_idle_service_reconnects_then_exits_after_cleanup(self):
        self.assertEqual(transport.run([str(self.admission), "idle", *self.roles[:2], str(self.authority)], timeout=45),
                         "idle-service-retired\n")

    def test_cancel_reaps_worker_and_preserves_accounting(self):
        result = self.invoke("cancel")
        self.assertEqual(result["host_cancellation"], "authority_changed")
        self.assertIsNotNone(result["worker_exit_code"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
