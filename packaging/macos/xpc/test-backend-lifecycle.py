#!/usr/bin/env python3
"""Ordinary failure handling for the disabled Apple backend, without launching it."""

from pathlib import Path
import subprocess
import tempfile
import unittest


class BackendLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="evx-apple-lifecycle-")
        cls.binary = Path(cls.temporary.name) / "lifecycle"
        subprocess.run(
            [
                "xcrun", "clang", "-std=c11", "-fblocks", "-Wall", "-Wextra",
                "-Werror", "-mmacosx-version-min=12.0",
                str(Path(__file__).with_name("backend-lifecycle.c")),
                "-framework", "CoreFoundation", "-framework", "Security",
                "-o", str(cls.binary),
            ],
            check=True,
            timeout=30,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], timeout=5)
        self.assertEqual(result.returncode, 0)

    def test_idle_exit_requires_cleanup_and_reconnect_fences_timer(self):
        self.run_case("idle")

    def test_stopped_child_status_is_not_reap_evidence(self):
        self.run_case("stopped")

    def test_worker_binding_rejects_writable_files_and_symlink_components(self):
        self.run_case("worker-binding")

    def test_stale_live_observation_is_rejected(self):
        self.run_case("stale")

    def test_observation_failure_is_terminal(self):
        self.run_case("observations")

    def test_missing_observations_do_not_prevent_termination(self):
        self.run_case("termination")

    def test_wait_interruption_is_retried(self):
        self.run_case("interrupted-wait")


if __name__ == "__main__":
    unittest.main(verbosity=2)
