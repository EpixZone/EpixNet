#!/usr/bin/env python3
"""Offline regressions for Linux bundle architecture and desktop registration."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("package_linux", HERE / "package-linux.py")
packaging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packaging)


def elf(path, machine=62, bits=2):
    header = bytearray(64)
    header[:6] = b"\x7fELF" + bytes([bits, 1])
    struct.pack_into("<H", header, 18, machine)
    path.write_bytes(header)
    path.chmod(0o755)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_32_bit_firefox_and_mixed_libxul(self):
        elf(self.root / "firefox", machine=3, bits=1)
        elf(self.root / "libxul.so")
        with self.assertRaisesRegex(ValueError, "expected 64-bit"):
            packaging.check_firefox(self.root, "x86_64")
        elf(self.root / "firefox")
        elf(self.root / "libxul.so", machine=183)
        with self.assertRaisesRegex(ValueError, "does not match"):
            packaging.check_firefox(self.root, "x86_64")

    def test_missing_browser_core_and_execute_permission_fail_closed(self):
        elf(self.root / "firefox")
        with self.assertRaisesRegex(ValueError, "Missing"):
            packaging.check_firefox(self.root, "x86_64")
        elf(self.root / "libxul.so")
        (self.root / "firefox").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "not executable"):
            packaging.check_firefox(self.root, "x86_64")

    def test_tampered_cached_tool_is_not_executed(self):
        digest = json.loads((HERE / "tools.json").read_text())["nfpm"]["sha256"]
        (self.root / f"nfpm-{digest}.download").write_bytes(b"not the pinned executable")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            packaging.tool("nfpm", self.root)
        self.assertFalse((self.root / "nfpm").exists())

    def sandbox_profile(self, path):
        return subprocess.check_output([
            "bash", str(HERE / "enable-sandbox.sh"), "--print-profile", "--firefox-path", path,
        ], text=True)

    def test_sandbox_permission_survives_appimage_remounts(self):
        self.assertEqual(
            self.sandbox_profile("/tmp/.mount_MyNameAb0123/usr/bin/firefox/firefox"),
            self.sandbox_profile("/tmp/.mount_MyNameCd4567/usr/bin/firefox/firefox"),
        )
        self.assertEqual(
            self.sandbox_profile("/tmp/.mount_EpixNeAb0123/usr/bin/firefox/firefox"),
            self.sandbox_profile("/opt/epixnet/firefox/firefox"),
        )
        self.assertEqual(
            self.sandbox_profile("/custom/appimage_extracted_123abc/usr/bin/firefox/firefox"),
            self.sandbox_profile("/custom/appimage_extracted_987def/usr/bin/firefox/firefox"),
        )

    def test_sandbox_rule_quotes_reserved_path_characters(self):
        profile = self.sandbox_profile('/tmp/space "quote" [a]*?@{x}\\path/firefox')
        self.assertIn(r'/tmp/space \"quote\" \[a\]\*\?\@\{x\}\\path/firefox{,-bin}', profile)
        if shutil.which("apparmor_parser"):
            rule = self.root / "rule"
            rule.write_text(profile)
            subprocess.run(["apparmor_parser", "--skip-kernel-load", "--skip-read-cache", str(rule)],
                           check=True, capture_output=True)

    def test_sandbox_rule_rejects_invalid_paths(self):
        for path in ("relative/firefox", "/tmp/foo\nbar/firefox", "/tmp/foo/bash"):
            result = subprocess.run([
                "bash", str(HERE / "enable-sandbox.sh"), "--print-profile", "--firefox-path", path,
            ], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_download_selects_correct_mozilla_architecture(self):
        script = self.root / "packaging/fetch-firefox-esr.sh"
        script.parent.mkdir()
        shutil.copy2(HERE.parent / "fetch-firefox-esr.sh", script)
        source = self.root / "source/firefox"
        source.mkdir(parents=True)
        elf(source / "firefox")
        elf(source / "libxul.so")
        archive = self.root / "fixture.tar.xz"
        with tarfile.open(archive, "w:xz") as tar:
            tar.add(source, arcname="firefox")
        bindir = self.root / "bin"
        bindir.mkdir()
        curl = bindir / "curl"
        curl.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n'
                        'while [ "$1" != "-o" ]; do shift; done\ncp "$ARCHIVE" "$2"\n')
        curl.chmod(0o755)
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                   ARCHIVE=str(archive), CAPTURE=str(self.root / "url"))
        for arch, product in (("x86_64", "linux64"), ("aarch64", "linux64-aarch64")):
            subprocess.run(["bash", str(script), "linux"], env=dict(env, EPIX_ARCH=arch),
                           check=True, capture_output=True)
            self.assertIn("&os=" + product + "&", (self.root / "url").read_text())
        result = subprocess.run(["bash", str(script), "linux"], env=dict(env, EPIX_ARCH="i686"),
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_relocated_tar_desktop_entry_launches_paths_with_reserved_characters(self):
        bundle = self.root / 'Epix & Space % "quote" $dollar `tick` \\ slash'
        bundle.mkdir()
        installer = (HERE / "build-linux.sh").read_text().split("<<'INSTALL'\n", 1)[1].split("\nINSTALL", 1)[0]
        (bundle / "install.sh").write_text(installer)
        shutil.copy2(HERE / "epix.desktop", bundle / "epix.desktop")
        for size in (48, 64, 128, 256, 512):
            icon = bundle / f"icons/hicolor/{size}x{size}/apps/epix.png"
            icon.parent.mkdir(parents=True)
            shutil.copy2(HERE / f"icons/epix-{size}.png", icon)
        browser = bundle / "epix-browser"
        browser.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$EPIX_TEST_ARGUMENTS"\n')
        browser.chmod(0o755)
        env = dict(os.environ, HOME=str(self.root / "home"), XDG_DATA_HOME=str(self.root / "data"),
                   XDG_CONFIG_HOME=str(self.root / "config"), XDG_CACHE_HOME=str(self.root / "cache"),
                   EPIX_TEST_ARGUMENTS=str(self.root / "args"))
        subprocess.run(["bash", str(bundle / "install.sh")], env=env, check=True, capture_output=True)
        desktop = self.root / "data/applications/epix.desktop"
        subprocess.run(["desktop-file-validate", str(desktop)], check=True, capture_output=True)
        subprocess.run(["gio", "launch", str(desktop), "epix://talk.epix/"],
                       env=env, check=True)
        for _ in range(40):
            if (self.root / "args").exists():
                break
            time.sleep(0.05)
        self.assertEqual((self.root / "args").read_text().strip(), "epix://talk.epix/")
        self.assertFalse((self.root / "home/.local/share/applications").exists())


if __name__ == "__main__":
    unittest.main()
