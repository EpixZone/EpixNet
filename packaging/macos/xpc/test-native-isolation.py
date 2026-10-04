#!/usr/bin/env python3
"""Probe native inherited sandbox authority with disposable signed service slots."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("package_backend", SOURCE / "package_backend.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


@unittest.skipUnless(sys.platform == "darwin", "macOS App Sandbox required")
class NativeIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="evx-native-isolation-")
        cls.root = Path(cls.temporary.name).resolve()
        cls.host_id = "org.epixnet.evx.native.fixture." + uuid.uuid4().hex
        common = ["xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra", "-Werror", "-mmacosx-version-min=12.0"]
        for role in ("host", "worker"):
            subprocess.run([*common, str(SOURCE / f"native-isolation-{role}.c"),
                            "-framework", "CoreFoundation", "-framework", "Security", "-o", str(cls.root / role)], check=True, timeout=30)
        entry = cls.root / "entry.c"
        entry.write_text("extern void evx_xpc_service_main(void); int main(void) { evx_xpc_service_main(); }\n")
        subprocess.run([*common, str(entry), str(SOURCE.parents[2] / "crates/evx-supervisor/native/apple_xpc.c"),
                        "-framework", "CoreFoundation", "-framework", "Security", "-o", str(cls.root / "service")], check=True, timeout=30)
        cls.app = cls.root / "NativeFixture.app"
        cls.verified = package.build(cls.app, cls.root / "host", cls.root / "worker", cls.root / "service", cls.host_id, slots=2)

    @classmethod
    def tearDownClass(cls):
        # Services own their workers and self-exit after 30 idle seconds. Never
        # signal a PID or remove OS container metadata during fixture cleanup.
        time.sleep(31)
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        identities = [cls.host_id] + [binding[role]["service"] for binding in cls.verified["manifest"]["slots"] for role in package.ROLES]
        for identity in identities:
            leaf = home / "Library/Containers" / identity / "Data/Library/Application Support/EpixNet"
            for name in ("NativeFixture", "EVXWorkspace", "EVXAuthority"):
                path = leaf / name
                if path.exists():
                    shutil.rmtree(path)
        cls.temporary.cleanup()

    def test_native_worker_cannot_access_other_slots_or_host_authority(self):
        slots = self.verified["manifest"]["slots"]
        args = [self.host_id]
        for binding in (slots[0]["guest"], slots[1]["guest"], slots[1]["file"]):
            args.extend([binding["service"], binding["requirement"]])
        completed = subprocess.run([str(self.app / "Contents/MacOS/host"), *args], capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(set(result), {"host_denied", "guest_denied", "file_denied", "own_allowed", "network_denied", "fork_denied", "spawn_denied", "limit_immutable", "descriptors_closed"})
        self.assertTrue(all(value == 1 for value in result.values()), result)
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
