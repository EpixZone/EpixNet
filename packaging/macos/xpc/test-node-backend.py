#!/usr/bin/env python3
"""Run actual node consent, files and scheduler through a signed development pool."""
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
REPO = SOURCE.parents[2]
os.environ.setdefault("CARGO_TARGET_DIR", str(REPO / "target/apple-xpc"))
spec = importlib.util.spec_from_file_location("package_backend", SOURCE / "package_backend.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


@unittest.skipUnless(sys.platform == "darwin", "macOS XPC required")
class NodeBackendTests(unittest.TestCase):
    def test_signed_node_manual_files_recovery_and_background_scheduler(self):
        subprocess.run(["cargo", "build", "-p", "epix-evx", "-p", "evx-worker", "-p", "evx-supervisor",
                        "--features", "epix-evx/apple-xpc-development,evx-worker/apple-xpc,evx-supervisor/apple-xpc",
                        "--bins", "--example", "apple_node_host", "--locked"], cwd=REPO, check=True, timeout=600)
        metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=REPO))
        binaries = Path(metadata["target_directory"]) / "debug"
        host_id = "org.epixnet.evx.node.fixture." + uuid.uuid4().hex
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        root = home / "Library/Containers" / host_id / "Data/Library/Application Support/EpixNet/DevelopmentFixtures" / uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="evx-node-apple-") as temporary:
            app = Path(temporary) / "NodeFixture.app"
            checked = package.build(app, binaries / "examples/apple_node_host", binaries / "evx-worker",
                                    binaries / "evx-xpc-service", host_id, slots=1)
            host = app / "Contents/MacOS/host"
            try:
                result = subprocess.run([str(host), "node", str(root), host_id], capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                payload = json.loads(result.stdout.strip().splitlines()[-1])
                self.assertEqual(payload, dict(manual=True, files=True, recovery=True, scheduler=True, revocation=True))
            finally:
                subprocess.run([str(host), "cleanup", str(root), host_id], check=True, timeout=30)
                # Suite-specific IDs only. Wait for idle service retirement; no PID signalling.
                time.sleep(31)
                for slot in checked["manifest"]["slots"]:
                    for role in ("guest", "compiler", "file"):
                        leaf = home / "Library/Containers" / slot[role]["service"] / "Data/Library/Application Support/EpixNet/EVXWorkspace"
                        if leaf.exists():
                            shutil.rmtree(leaf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
