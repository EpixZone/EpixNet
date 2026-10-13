#!/usr/bin/env python3
"""Sacrificial package fixtures. These tests do not execute an EVX worker."""

import importlib.util
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("evx_package", HERE / "verify-evx-package.py")
package = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="evx-package-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name) / "Fixture.app"
        self.macos = self.app / "Contents" / "MacOS"
        self.macos.mkdir(parents=True)
        self.worker = self.macos / "evx-worker"
        self.worker.write_bytes(b"\xcf\xfa\xed\xfe" + b"fixture")
        self.worker.chmod(0o755)
        self.entitlements = {}
        self.dependencies = ["/usr/lib/libSystem.B.dylib"]
        self.calls = []

    def tool(self, command):
        self.calls.append(command)
        if command[0] == "/usr/bin/otool":
            return (str(self.worker) + ":\n" + "".join(
                f"\t{name} (compatibility version 1.0.0, current version 1.0.0)\n"
                for name in self.dependencies
            )).encode()
        if "--entitlements" in command:
            return plistlib.dumps(self.entitlements)
        return b""

    def check(self, profile="direct-child"):
        return package.verify(self.app, profile=profile, run_tool=self.tool)

    def test_signed_direct_package_checks_app_and_worker_separately(self):
        result = self.check()
        self.assertFalse(result["app_store_ready"])
        self.assertEqual(result["profile"], "direct-child")
        checked = [c[-1] for c in self.calls if "--verify" in c]
        self.assertEqual(checked, [str(self.worker), str(self.app)])

    def test_app_store_is_denied_even_with_an_xpc_named_bundle(self):
        xpc = self.app / "Contents" / "XPCServices" / "EVXGuest.xpc"
        xpc.mkdir(parents=True)
        with self.assertRaisesRegex(package.PackageError, "XPC transport"):
            self.check("app-store")
        self.assertEqual(self.calls, [])

    def test_missing_worker_is_denied(self):
        self.worker.unlink()
        with self.assertRaisesRegex(package.PackageError, "missing"):
            self.check()

    def test_worker_symlink_is_denied(self):
        target = self.worker.with_name("other")
        self.worker.rename(target)
        self.worker.symlink_to(target)
        with self.assertRaisesRegex(package.PackageError, "symlink"):
            self.check()

    def test_parent_directory_symlink_is_denied(self):
        target = self.macos.with_name("Alternate")
        self.macos.rename(target)
        self.macos.symlink_to(target)
        with self.assertRaisesRegex(package.PackageError, "symlink"):
            self.check()

    def test_non_macho_or_non_executable_worker_is_denied(self):
        self.worker.write_bytes(b"#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(package.PackageError, "Mach-O"):
            self.check()
        self.worker.write_bytes(b"\xcf\xfa\xed\xfe")
        self.worker.chmod(0o644)
        with self.assertRaisesRegex(package.PackageError, "executable"):
            self.check()

    def test_signature_check_failure_is_not_ignored(self):
        def failed(_command):
            raise package.PackageError("signature failed")
        with self.assertRaisesRegex(package.PackageError, "signature failed"):
            package.verify(self.app, profile="direct-child", run_tool=failed)

    def test_entitlement_expansions_are_denied(self):
        for key, value in [
            ("com.apple.security.network.client", True),
            ("com.apple.security.app-sandbox", True),
            ("com.apple.security.inherit", True),
            ("com.apple.security.application-groups", ["group.fixture"]),
            ("com.apple.security.cs.allow-jit", True),
            ("com.apple.security.cs.allow-unsigned-executable-memory", True),
            ("com.apple.security.cs.disable-library-validation", True),
            ("com.apple.security.get-task-allow", True),
            ("fixture.unknown-capability", "enabled"),
        ]:
            with self.subTest(key=key):
                self.entitlements = {key: value}
                with self.assertRaisesRegex(package.PackageError, "entitlement"):
                    self.check()

    def test_signing_metadata_is_allowed(self):
        self.entitlements = {
            "application-identifier": "FIXTURE.zone.epix.worker",
            "com.apple.developer.team-identifier": "FIXTURE",
            "com.apple.security.get-task-allow": False,
        }
        self.check()

    def test_malformed_entitlements_are_denied(self):
        ordinary = self.tool
        for data in (b"not a plist", b'<?xml version="1.0"?><plist><dict>'):
            with self.subTest(data=data):
                def malformed(command):
                    return data if "--entitlements" in command else ordinary(command)
                with self.assertRaisesRegex(package.PackageError, "entitlements"):
                    package.verify(self.app, profile="direct-child", run_tool=malformed)

    def test_non_system_and_ambiguous_dependencies_are_denied(self):
        for dependency in [
            "/opt/homebrew/lib/libfixture.dylib", "@rpath/libfixture.dylib",
            "@executable_path/libfixture.dylib", "/usr/lib/../../tmp/libfixture.dylib",
            "/System/LibraryExtra/libfixture.dylib", "relative.dylib",
        ]:
            with self.subTest(dependency=dependency):
                self.dependencies = [dependency]
                with self.assertRaisesRegex(package.PackageError, "dependency"):
                    self.check()

    def test_system_framework_dependency_is_allowed(self):
        self.dependencies.append("/System/Library/Frameworks/Security.framework/Versions/A/Security")
        self.check()

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"), "macOS CLT required")
    def test_real_ad_hoc_fixture_signature_and_tamper(self):
        # This executable only returns zero. It is never launched.
        subprocess.run(["clang", "-x", "c", "-", "-o", str(self.worker)],
                       input=b"int main(void) { return 0; }\n", check=True, capture_output=True)
        launcher = self.macos / "epix-browser"
        shutil.copyfile(self.worker, launcher)
        launcher.chmod(0o755)
        info = {
            "CFBundleIdentifier": "zone.epix.fixture.package",
            "CFBundleExecutable": "epix-browser",
            "CFBundlePackageType": "APPL",
        }
        (self.app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
        for target in (self.worker, self.app):
            subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(target)],
                           check=True, capture_output=True)
        result = package.verify(self.app, profile="direct-child")
        self.assertFalse(result["app_store_ready"])
        with self.worker.open("ab") as out:
            out.write(b"fixture tamper")
        with self.assertRaisesRegex(package.PackageError, "codesign"):
            package.verify(self.app, profile="direct-child")


if __name__ == "__main__":
    unittest.main()
