#!/usr/bin/env python3
"""Offline regressions for the Firefox ESR release selected for each bundle."""
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse


HERE = Path(__file__).resolve().parent


class FirefoxDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / "packaging/fetch-firefox-esr.sh"
        self.script.parent.mkdir()
        shutil.copy2(HERE / "fetch-firefox-esr.sh", self.script)
        self.out = self.script.parent / "firefox-esr"
        self.capture = self.root / "curl-arguments"
        self.source = self.root / "source"
        firefox = self.source / "firefox"
        firefox.mkdir(parents=True)
        (firefox / "firefox").write_text("#!/bin/sh\nexit 0\n")
        (firefox / "firefox").chmod(0o755)
        (firefox / "libxul.so").touch()
        (self.source / "Firefox.app").mkdir()
        (self.source / "Firefox.app/fixture").touch()
        (self.source / "core").mkdir()
        (self.source / "core/firefox.exe").touch()
        archive = self.root / "fixture.tar.xz"
        with tarfile.open(archive, "w:xz") as tar:
            tar.add(firefox, arcname="firefox")

        bindir = self.root / "bin"
        bindir.mkdir()
        tempdir = self.root / "tmp"
        tempdir.mkdir()
        stubs = {
            "curl": '''#!/bin/sh
printf '%s\n' "$@" > "$EPIX_TEST_CAPTURE"
if [ "${EPIX_TEST_HTTP_FAILURE:-0}" = 1 ]; then exit 22; fi
while [ "$1" != -o ]; do shift; done
cp "$EPIX_TEST_ARCHIVE" "$2"
''',
            "hdiutil": '''#!/bin/sh
if [ "$1" = attach ]; then
  while [ "$1" != -mountpoint ]; do shift; done
  cp -R "$EPIX_TEST_SOURCE/Firefox.app" "$2/Firefox.app"
fi
''',
            "7z": '''#!/bin/sh
for arg do
  case "$arg" in
    -o*) mkdir -p "${arg#-o}"; cp -R "$EPIX_TEST_SOURCE/core" "${arg#-o}/core" ;;
  esac
done
''',
        }
        for name, content in stubs.items():
            executable = bindir / name
            executable.write_text(content)
            executable.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                        TMPDIR=str(tempdir),
                        EPIX_TEST_CAPTURE=str(self.capture), EPIX_TEST_SOURCE=str(self.source),
                        EPIX_TEST_ARCHIVE=str(archive))
        for variable in ("EPIX_FF_VERSION", "EPIX_FF_LANG", "EPIX_ARCH"):
            self.env.pop(variable, None)

    def fetch(self, platform, **env):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(self.script), platform],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def assert_download(self, result, product, platform, language="en-US"):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = self.capture.read_text().splitlines()
        url = urlparse(arguments[-1])
        self.assertEqual((url.scheme, url.netloc), ("https", "download.mozilla.org"))
        self.assertEqual(parse_qs(url.query), {
            "product": [product], "os": [platform], "lang": [language],
        })

    def test_every_platform_uses_the_pinned_esr_instead_of_the_latest_alias(self):
        for platform, arch, mozilla in (
            ("osx", "x86_64", "osx"),
            ("win64", "x86_64", "win64"),
            ("linux", "x86_64", "linux64"),
            ("linux", "aarch64", "linux64-aarch64"),
        ):
            with self.subTest(platform=platform, arch=arch):
                result = self.fetch(platform, EPIX_ARCH=arch)
                self.assert_download(result, "firefox-153.4.0esr-ssl", mozilla)

    def test_explicit_esr_override_and_language_apply_to_every_platform(self):
        for platform, mozilla in (("osx", "osx"), ("win64", "win64"), ("linux", "linux64")):
            with self.subTest(platform=platform):
                result = self.fetch(platform, EPIX_ARCH="x86_64", EPIX_FF_VERSION="153.5.0esr",
                                    EPIX_FF_LANG="de")
                self.assert_download(result, "firefox-153.5.0esr-ssl", mozilla, "de")

    def test_http_errors_fail_before_replacing_an_existing_browser(self):
        for platform in ("osx", "win64", "linux"):
            with self.subTest(platform=platform):
                browser = self.out / ("Firefox.app" if platform == "osx" else "firefox")
                browser.mkdir(parents=True, exist_ok=True)
                sentinel = browser / "existing-browser"
                sentinel.write_text("keep this bundle")
                result = self.fetch(platform, EPIX_ARCH="x86_64", EPIX_TEST_HTTP_FAILURE="1")
                self.assertEqual(result.returncode, 22, result.stdout + result.stderr)
                self.assertIn("--fail", self.capture.read_text().splitlines())
                self.assertEqual(sentinel.read_text(), "keep this bundle")

    def test_invalid_versions_are_rejected_before_downloading(self):
        for version in ("latest", "153.4.0", "153.4.0esr&os=linux", "../153.4.0esr"):
            with self.subTest(version=version):
                result = self.fetch("linux", EPIX_ARCH="x86_64", EPIX_FF_VERSION=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
