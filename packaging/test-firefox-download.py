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
if [ -n "${EPIX_TEST_CURL_LOG:-}" ]; then
  echo called >> "$EPIX_TEST_CURL_LOG"
  sleep 0.2
fi
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

    def fetch(self, platform, *args, **env):
        self.capture.unlink(missing_ok=True)
        return subprocess.run(["bash", str(self.script), platform, *args],
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

    def test_cached_linux_runtime_can_be_reused_offline_but_default_still_downloads(self):
        env = {"EPIX_ARCH": "x86_64"}
        self.assert_download(self.fetch("linux", "--if-needed", **env), "firefox-153.4.0esr-ssl", "linux64")
        offline = self.fetch("linux", "--if-needed", **env, EPIX_TEST_HTTP_FAILURE="1")
        self.assertEqual(offline.returncode, 0, offline.stderr)
        self.assertFalse(self.capture.exists())
        self.assert_download(self.fetch("linux", **env), "firefox-153.4.0esr-ssl", "linux64")
        self.assertEqual({p.name for p in (self.out / "firefox").iterdir()}, {"firefox", "libxul.so"})

    def test_changed_linux_version_language_or_architecture_requires_a_fetch(self):
        for version, lang, arch, mozilla in (
            ("153.4.0esr", "en-US", "x86_64", "linux64"),
            ("153.5.0esr", "en-US", "x86_64", "linux64"),
            ("153.5.0esr", "de", "x86_64", "linux64"),
            ("153.5.0esr", "de", "aarch64", "linux64-aarch64"),
        ):
            with self.subTest(version=version, lang=lang, arch=arch):
                self.assert_download(self.fetch("linux", "--if-needed", EPIX_ARCH=arch, EPIX_FF_LANG=lang,
                                                EPIX_FF_VERSION=version), f"firefox-{version}-ssl", mozilla, lang)

    def test_missing_linux_runtime_files_are_restored(self):
        env = {"EPIX_ARCH": "x86_64"}
        self.assertEqual(self.fetch("linux", **env).returncode, 0)
        for name in ("firefox", "libxul.so"):
            with self.subTest(name=name):
                (self.out / "firefox" / name).unlink()
                self.assert_download(self.fetch("linux", "--if-needed", **env), "firefox-153.4.0esr-ssl", "linux64")

    def test_cached_concurrent_calls_make_one_download(self):
        log = self.root / "curl-calls"
        args = ["bash", str(self.script), "linux", "--if-needed"]
        env = dict(self.env, EPIX_ARCH="x86_64", EPIX_TEST_CURL_LOG=str(log))
        with subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as first, \
             subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as second:
            for proc in (first, second):
                _, err = proc.communicate(timeout=10)
                self.assertEqual(proc.returncode, 0, err)
        self.assertEqual(log.read_text().splitlines(), ["called"])

    def test_cache_is_opt_in_only_for_linux(self):
        for args in (("linux", "--wrong"), ("osx", "--if-needed"), ("win64", "--if-needed")):
            with self.subTest(args=args):
                self.assertNotEqual(self.fetch(*args).returncode, 0)
                self.assertFalse(self.capture.exists())

    def test_failed_refresh_does_not_mark_or_replace_the_previous_linux_runtime(self):
        env = {"EPIX_ARCH": "x86_64"}
        self.assertEqual(self.fetch("linux", **env).returncode, 0)
        sentinel = self.out / "firefox" / "existing-browser"
        sentinel.write_text("prior runtime")
        broken = self.root / "incomplete.tar.xz"
        with tarfile.open(broken, "w:xz") as tar:
            tar.add(self.source / "firefox/firefox", arcname="firefox/firefox")
        for failure in ({"EPIX_TEST_HTTP_FAILURE": "1"}, {"EPIX_TEST_ARCHIVE": str(broken)}):
            with self.subTest(failure=failure):
                result = self.fetch("linux", "--if-needed", EPIX_FF_VERSION="153.5.0esr", **env, **failure)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(self.capture.exists())
                self.assertEqual(sentinel.read_text(), "prior runtime")
                previous = self.fetch("linux", "--if-needed", EPIX_TEST_HTTP_FAILURE="1", **env)
                self.assertEqual(previous.returncode, 0, previous.stderr)
                self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
