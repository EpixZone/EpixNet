#!/usr/bin/env python3
"""Signed fixed-pool packaging checks. Inert binaries do not prove runtime containment."""
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("package_backend", HERE / "package_backend.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


@unittest.skipUnless(sys.platform == "darwin", "macOS signing tools required")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="evx-pool-package-")
        cls.root = Path(cls.temporary.name).resolve()
        source = cls.root / "inert.c"
        source.write_text("int main(void) { return 0; }\n")
        cls.binary = cls.root / "inert"
        subprocess.run(["xcrun", "clang", str(source), "-o", str(cls.binary)], check=True, timeout=30)
        cls.original = cls.root / "Game.app"
        cls.checked = package.build(cls.original, cls.binary, cls.binary, cls.binary,
                                    "org.epixnet.evx.package.fixture", slots=2)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.app = self.root / (self._testMethodName + ".app")
        shutil.copytree(self.original, self.app)
        binding = self.checked["manifest"]["slots"][0]["guest"]
        self.service = self.app / "Contents" / "XPCServices" / (binding["service"] + ".xpc")
        self.worker = self.service / "Contents" / "MacOS" / "evx-worker-apple"

    def tearDown(self):
        shutil.rmtree(self.app)

    def test_signed_pool_has_separate_role_identities(self):
        result = package.verify(self.app)
        self.assertEqual((result["slots"], result["services"]), (2, 6))
        self.assertFalse(result["app_store_ready"])
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["runtime_containment_verified"])

    def test_changed_worker_bytes_are_rejected(self):
        with self.worker.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_worker_symlink_is_rejected(self):
        self.worker.unlink()
        self.worker.symlink_to(self.binary)
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_role_changes_remain_rejected_after_resigning(self):
        info_path = self.service / "Contents" / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        info["EVXRole"] = "file"
        info_path.write_bytes(plistlib.dumps(info))
        name = info["CFBundleIdentifier"]
        package.sign(self.service, name, package.SANDBOX, self.root)
        package.sign(self.app, self.checked["manifest"]["host_identifier"], package.SANDBOX, self.root)
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_network_entitlement_rejected_after_resigning(self):
        name = self.checked["manifest"]["slots"][0]["guest"]["service"]
        package.sign(self.service, name, {**package.SANDBOX, "com.apple.security.network.client": True}, self.root)
        package.sign(self.app, self.checked["manifest"]["host_identifier"], package.SANDBOX, self.root)
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_duplicate_manifest_key_rejected(self):
        path = self.app / "Contents" / "Resources" / package.MANIFEST
        path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_unknown_host_executable_rejected(self):
        shutil.copy2(self.binary, self.app / "Contents" / "MacOS" / "other")
        package.sign(self.app, self.checked["manifest"]["host_identifier"], package.SANDBOX, self.root)
        with self.assertRaises(package.PackageError):
            package.verify(self.app)

    def test_builder_never_replaces_existing_output(self):
        with self.assertRaises(package.PackageError):
            package.build(self.app, self.binary, self.binary, self.binary, "org.epixnet.evx.package.fixture")


if __name__ == "__main__":
    unittest.main(verbosity=2)
