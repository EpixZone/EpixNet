#!/usr/bin/env python3
"""Offline EVX packaging checks. Fixture ELF headers are never executed."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("package_linux", HERE / "package-linux.py")
packaging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packaging)


def elf(path, machine=62):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, machine)
    path.write_bytes(header)
    path.chmod(0o755)


class EvxPackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stage = self.root / "epix-linux"
        for name in ("epix-browser", "epix-nmh", "epix-server", "evx-worker",
                     "firefox/firefox", "firefox/libxul.so", "firefox/libepix-sandbox-probe.so"):
            elf(self.stage / name)
        policy = self.stage / "firefox/distribution/policies.json"
        policy.parent.mkdir()
        policy.write_text(json.dumps({"policies": {"Certificates": {"Install": ["epix-ca.pem"]}}}))
        for size in (48, 64, 128, 256, 512):
            icon = self.stage / f"icons/hicolor/{size}x{size}/apps/epix.png"
            icon.parent.mkdir(parents=True)
            icon.write_bytes(b"fixture icon")
        (self.stage / "LICENSE").write_text("fixture license")

    def tearDown(self):
        self.temp.cleanup()

    def test_missing_worker_is_rejected(self):
        (self.stage / "evx-worker").unlink()
        with self.assertRaises((ValueError, OSError)):
            packaging.validate_stage(self.stage)

    def test_worker_architecture_must_match_the_node(self):
        elf(self.stage / "evx-worker", machine=183)
        with self.assertRaisesRegex(ValueError, "evx-worker"):
            packaging.validate_stage(self.stage)

    def test_worker_must_be_executable(self):
        (self.stage / "evx-worker").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "evx-worker"):
            packaging.validate_stage(self.stage)

    def test_worker_cannot_be_a_symlink(self):
        worker = self.stage / "evx-worker"
        worker.unlink()
        outside = self.root / "substitute"
        elf(outside)
        worker.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "evx-worker"):
            packaging.validate_stage(self.stage)

    def test_install_check_rejects_missing_symlinked_or_nonexecutable_worker(self):
        script = (HERE / "test-install.sh").read_text()
        function = "check_evx_worker() {" + script.split("check_evx_worker() {", 1)[1].split("\n}", 1)[0] + "\n}"
        command = ["bash", "-c", function + '\ncheck_evx_worker "$1"', "fixture", str(self.stage)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        worker = self.stage / "evx-worker"
        for kind in ("missing", "symlink", "nonexecutable"):
            with self.subTest(kind=kind):
                worker.unlink(missing_ok=True)
                if kind == "symlink":
                    worker.symlink_to(self.stage / "epix-server")
                elif kind == "nonexecutable":
                    elf(worker)
                    worker.chmod(0o644)
                self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_native_packages_include_the_worker_beside_the_node(self):
        work = self.root / "work"
        work.mkdir()

        def command(*args, **kwargs):
            output = "shlibs:Depends=libc6 (>= 2.35)" if args[0] == "dpkg-shlibdeps" else ""
            return subprocess.CompletedProcess(args, 0, output, "")

        with mock.patch.object(packaging, "run", side_effect=command):
            config = packaging.native_config(self.stage, "0.1.0", "x86_64", work,
                                             packaging.elf_files(self.stage))
        self.assertIn({"src": str(self.stage / "evx-worker"), "dst": "/opt/epixnet/evx-worker"},
                      config["contents"])

    def test_appimage_includes_the_worker_beside_the_node(self):
        work = self.root / "work"
        work.mkdir()
        with mock.patch.object(packaging, "tool", side_effect=lambda name, _: self.root / name), \
             mock.patch.object(packaging, "run", return_value=subprocess.CompletedProcess([], 0, "/fixture/lib", "")):
            packaging.appimage(self.stage, self.root, "0.1.0", work, self.root / "cache")
        worker = work / "EpixNet.AppDir/usr/bin/evx-worker"
        self.assertTrue(worker.is_file(), "AppImage omitted the worker")
        self.assertEqual(worker.read_bytes(), (self.stage / "evx-worker").read_bytes())

    def test_tar_keeps_the_validated_worker(self):
        args = ["package-linux.py", "--stage", str(self.stage), "--output", str(self.root / "out"),
                "--version", "0.1.0", "--formats", "tar"]
        with mock.patch.object(sys, "argv", args), \
             mock.patch.object(packaging, "glibc_requirement", return_value="2.35"):
            packaging.main()
        with tarfile.open(self.root / "out/epix-linux-0.1.0.tar.gz") as archive:
            worker = archive.getmember("epix-linux/evx-worker")
            self.assertTrue(worker.isfile())
            self.assertTrue(worker.mode & 0o111)
            self.assertEqual(archive.extractfile(worker).read(), (self.stage / "evx-worker").read_bytes())

    def test_build_script_builds_and_stages_the_worker(self):
        repo = self.root / "repo"
        package = repo / "packaging/linux"
        package.mkdir(parents=True)
        shutil.copy2(HERE / "build-linux.sh", package / "build-linux.sh")
        shutil.copy2(HERE / "epix.desktop", package / "epix.desktop")
        # Isolate staging from compiler, browser downloads and package tools.
        (package / "package-linux.py").write_text("pass\n")
        (repo / "LICENSE").write_text("fixture license")
        for size in (48, 64, 128, 256, 512):
            icon = package / f"icons/epix-{size}.png"
            icon.parent.mkdir(exist_ok=True)
            icon.write_bytes(b"fixture icon")
        for name in ("epix-browser", "epix-nmh", "epix-server", "evx-worker"):
            elf(repo / "target/release" / name)
        stubs = self.root / "stubs"
        stubs.mkdir()
        cargo = stubs / "cargo"
        capture = self.root / "cargo-args"
        cargo.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(str(capture)) + "\n")
        cargo.chmod(0o755)
        cc = stubs / "cc"
        cc.write_text('#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\n: > "$2"\n')
        cc.chmod(0o755)
        environment = dict(os.environ, PATH=str(stubs) + os.pathsep + os.environ["PATH"],
                           CC=str(cc), EPIX_VERSION="0.1.0", EPIX_FORMATS="tar", EPIX_SKIP_BUILD="0",
                           CARGO_TARGET_DIR=str(repo / "target"), EPIX_BUNDLE_FIREFOX=str(self.stage / "firefox"))
        subprocess.run(["bash", str(package / "build-linux.sh"), str(self.root / "out")],
                       env=environment, check=True, capture_output=True)
        self.assertIn("evx-worker", capture.read_text().splitlines(), "release build omitted the worker")
        self.assertEqual((self.root / "out/epix-linux/evx-worker").read_bytes(),
                         (repo / "target/release/evx-worker").read_bytes())


if __name__ == "__main__":
    unittest.main()
