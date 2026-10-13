#!/usr/bin/env python3
"""Ad-hoc tests of production package policy/bootstrap, never release signing."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
os.environ.setdefault("CARGO_TARGET_DIR", str(REPO / "target/apple-xpc"))
spec = importlib.util.spec_from_file_location("release_pool", HERE / "release_pool.py")
package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)

@unittest.skipUnless(sys.platform == "darwin", "macOS signing required")
class ReleasePoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-p", "evx-supervisor", "-p", "evx-worker", "-p", "epix-evx",
            "--features", "evx-supervisor/apple-xpc,evx-worker/apple-xpc,epix-evx/apple-xpc-development",
            "--bins", "--example", "apple_package_host", "--example", "apple_node_host", "--locked", "--offline"], cwd=REPO, check=True, timeout=600)
        cls.bin = Path(json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=REPO))["target_directory"]) / "debug"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evx-release-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.host_id = "org.epixnet.evx.release.fixture." + uuid.uuid4().hex
        self.container = Path(pwd.getpwuid(os.geteuid()).pw_dir) / "Library/Containers" / self.host_id
        self.private = self.container / "Data/Library/Application Support/EpixNet"
        self.app = self.root / "Game.app"
        self.main = self.app / "Contents/MacOS/host"
        self.main.parent.mkdir(parents=True)
        source = "apple_node_host" if self._testMethodName in ("test_node_manual_scheduler_and_recovery_use_verified_package", "test_installed_application_runs_with_system_admin_parent") else "apple_package_host"
        shutil.copy2(self.bin / "examples" / source, self.main)
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier":self.host_id,"CFBundleExecutable":"host","CFBundlePackageType":"APPL","CFBundleVersion":"1"}))
        self.checked = package.assemble(self.app, self.bin / "evx-worker", self.bin / "evx-xpc-service", "", "-", slots=1, fixture=True)
        self.running = False

    def tearDown(self):
        if self.running:
            time.sleep(31)
        if self.container.exists():
            # Host is unsandboxed in this profile. Only this unique fixture's
            # own mutable data is removed; OS container metadata is untouched.
            shutil.rmtree(self.container / "Data", ignore_errors=True)
        for slot in self.checked["manifest"]["slots"]:
            for role in package.base.ROLES:
                data = self.container.parent / slot[role]["service"] / "Data/Library/Application Support/EpixNet/EVXWorkspace"
                if data.exists(): shutil.rmtree(data)
        if self.app.parent == Path("/Applications") and self.app.exists():
            shutil.rmtree(self.app)
        self.temp.cleanup()

    def run_host(self, *args):
        return subprocess.run([str(self.main), *args], capture_output=True, text=True, timeout=90)

    def test_signed_bootstrap_retains_registry_across_relaunch(self):
        first = self.run_host(); second = self.run_host()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(first.stdout), json.loads(second.stdout))
        self.assertTrue(str(self.private / "EVXProduction") in first.stdout)

    def test_production_entry_refuses_ad_hoc_profile(self):
        result = self.run_host("strict")
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertFalse((self.private / "EVXProduction").exists())
        with self.assertRaises(package.PackageError): package.inspect_manifest(self.app, "ABCDEFGHIJ", False)

    def test_lost_registry_does_not_reprovision(self):
        self.assertEqual(self.run_host().returncode, 0)
        shutil.rmtree(self.private / "EVXProduction/registry")
        self.assertEqual(self.run_host().returncode, 3)
        self.assertFalse((self.private / "EVXProduction/registry").exists())

    def test_existing_service_container_blocks_first_provision(self):
        service = self.checked["manifest"]["slots"][0]["file"]["service"]
        path = self.container.parent / service
        path.mkdir()
        self.assertEqual(self.run_host().returncode, 3)
        self.assertFalse((self.private / "EVXProduction/registry").exists())
        # macOS owns this container root once named. Leave its empty metadata
        # directory; never bypass the OS removal restriction.

    def test_manifest_change_cannot_select_another_pool(self):
        path = self.app / "Contents/Resources/evx-services.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.assertEqual(self.run_host().returncode, 3)

    def test_wrong_compiled_team_and_non_adapter_host_are_rejected(self):
        with self.assertRaises(package.PackageError):
            package.host_build_policy(self.main, "ABCDEFGHIJ")
        with self.assertRaises(package.PackageError):
            package.host_build_policy(Path("/usr/bin/true"), "")

    def test_verifier_rejects_group_writable_bundle(self):
        self.app.chmod(0o775)
        with self.assertRaises(package.PackageError):
            package.inspect_manifest(self.app, "", True)

    def test_verifier_rejects_symlink_bundle(self):
        alias = self.root / "Alias.app"
        alias.symlink_to(self.app)
        with self.assertRaises(package.PackageError):
            package.inspect_manifest(alias, "", True)

    def test_release_assembly_never_silently_ad_hoc_signs(self):
        with self.assertRaises(package.PackageError):
            package.assemble(self.app, self.bin / "evx-worker", self.bin / "evx-xpc-service", "ABCDEFGHIJ", "-")

    def test_installed_application_runs_with_system_admin_parent(self):
        installed = Path("/Applications") / ("EVX-" + uuid.uuid4().hex + ".app")
        self.app.rename(installed)
        self.app = installed
        self.main = installed / "Contents/MacOS/host"
        self.test_node_manual_scheduler_and_recovery_use_verified_package()

    def test_node_manual_scheduler_and_recovery_use_verified_package(self):
        self.running = True
        root = self.private / "DevelopmentFixtures" / uuid.uuid4().hex
        result = self.run_host("package-node", str(root), self.host_id)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]), dict(manual=True,files=True,recovery=True,scheduler=True,revocation=True))

if __name__ == "__main__": unittest.main(verbosity=2)
