#!/usr/bin/env python3
"""Exercise Linux autostart with the real module and desktop entry launcher."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]


class AutostartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for command in ("rustc", "gio", "desktop-file-validate"):
            if not shutil.which(command):
                raise RuntimeError(f"Required test dependency is missing: {command}")
        cls.build = tempfile.TemporaryDirectory(prefix="epix-autostart-build-")
        cls.addClassCleanup(cls.build.cleanup)
        build = Path(cls.build.name)
        source = build / "main.rs"
        module = json.dumps(str(ROOT / "crates/epix-browser/src/autostart.rs"), ensure_ascii=False)
        source.write_text(
            f"#[path = {module}]\nmod autostart;\n"
            r'''
fn main() {
    let args: Vec<String> = std::env::args_os().skip(1)
        .map(|arg| arg.into_string().unwrap()).collect();
    match args.first().map(String::as_str) {
        Some("--background") => {
            let capture = std::env::var_os("EPIX_TEST_AUTOSTART_CAPTURE").unwrap();
            std::fs::write(capture, format!("native\n{}\n", args.join("\n"))).unwrap();
        }
        Some("enable") | Some("disable") => {
            if let Err(error) = autostart::set_enabled(args[0] == "enable") {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Some("refresh") => {
            if let Err(error) = autostart::refresh_enabled() {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Some("status") => println!("{}", autostart::is_enabled()),
        _ => std::process::exit(2),
    }
}
'''
        )
        cls.harness = build / "epix-browser"
        compiled = subprocess.run(
            ["rustc", "--edition=2021", str(source), "-o", str(cls.harness)],
            capture_output=True, text=True, timeout=60,
        )
        if compiled.returncode:
            raise RuntimeError(compiled.stdout + compiled.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="epix-autostart-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ)
        for name in ("APPIMAGE", "APPDIR", "APPIMAGE_EXTRACT_AND_RUN"):
            self.env.pop(name, None)
        for name, folder in (
            ("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"),
        ):
            directory = self.root / folder
            directory.mkdir(mode=0o700)
            self.env[name] = str(directory)
        self.capture = self.root / "captured-arguments"
        self.env["EPIX_TEST_AUTOSTART_CAPTURE"] = str(self.capture)
        self.mode = self.root / "captured-extraction-mode"
        self.env["EPIX_TEST_AUTOSTART_MODE"] = str(self.mode)
        self.desktop = self.root / "config/autostart/epixnet.desktop"

    def browser(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.harness, path)
        return path

    def appimage(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '#!/bin/sh\n'
            'printf "%s" "${APPIMAGE_EXTRACT_AND_RUN-}" > "$EPIX_TEST_AUTOSTART_MODE"\n'
            'printf "appimage\\n%s\\n" "$@" > "$EPIX_TEST_AUTOSTART_CAPTURE"\n'
        )
        path.chmod(0o755)
        return path

    def run_browser(self, browser, action, *, check=True):
        result = subprocess.run(
            [str(browser), action], env=self.env, cwd=self.root,
            capture_output=True, text=True, timeout=10,
        )
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def launch(self, expected):
        subprocess.run(
            ["desktop-file-validate", str(self.desktop)],
            env=self.env, check=True, capture_output=True, text=True, timeout=10,
        )
        launched = subprocess.run(
            ["gio", "launch", str(self.desktop)], env=self.env,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(launched.returncode, 0, launched.stdout + launched.stderr)
        deadline = time.monotonic() + 3
        arguments = None
        while time.monotonic() < deadline:
            if self.capture.exists():
                arguments = self.capture.read_text().splitlines()
                if arguments == [expected, "--background"]:
                    break
            time.sleep(0.025)
        self.assertTrue(self.capture.exists(), "Autostart executable was not launched")
        self.assertEqual(arguments, [expected, "--background"])

    def enable_appimage(self, outer_name="EpixNet.AppImage", appdir_name=".mount_EpixNe123456"):
        appdir = self.root / appdir_name
        browser = self.browser(appdir / "usr/bin/epix-browser")
        outer = self.appimage(self.root / "Applications" / outer_name)
        self.env.update(APPDIR=str(appdir), APPIMAGE=str(outer))
        self.run_browser(browser, "enable")
        self.assertEqual(self.run_browser(browser, "status").stdout.strip(), "true")
        shutil.rmtree(appdir)

    def test_appimage_autostart_survives_unmount(self):
        self.enable_appimage()
        self.launch("appimage")
        self.assertEqual(self.mode.read_text(), "")

    def test_appimage_path_preserves_desktop_reserved_characters(self):
        self.enable_appimage('Epix %f "quote" $dollar `tick` \\ equals= ;&()|<>*? \'single\'.AppImage')
        self.launch("appimage")

    def test_native_install_still_launches_its_executable(self):
        browser = self.browser(self.root / "native install/epix-browser")
        self.run_browser(browser, "enable")
        self.launch("native")
        self.run_browser(browser, "disable")
        self.assertEqual(self.run_browser(browser, "status").stdout.strip(), "false")
        self.assertFalse(self.desktop.exists())
        self.run_browser(browser, "disable")

    def test_native_install_ignores_stale_appimage_environment(self):
        browser = self.browser(self.root / "native/epix-browser")
        outer = self.appimage(self.root / "Applications/Stale.AppImage")
        for appdir in (None, str(self.root / ".mount_Another123456")):
            with self.subTest(appdir=appdir):
                self.env["APPIMAGE"] = str(outer)
                if appdir is None:
                    self.env.pop("APPDIR", None)
                else:
                    self.env["APPDIR"] = appdir
                self.run_browser(browser, "enable")
                self.launch("native")
                self.capture.unlink()

    def test_manually_extracted_appdir_ignores_inherited_appimage_path(self):
        appdir = self.root / "manual-extraction"
        browser = self.browser(appdir / "usr/bin/epix-browser")
        outer = self.appimage(self.root / "Applications/Stale.AppImage")
        self.env.update(APPDIR=str(appdir), APPIMAGE=str(outer))
        self.run_browser(browser, "enable")
        self.launch("native")

    def test_invalid_appimage_path_leaves_existing_entry_untouched(self):
        appdir = self.root / ".mount_EpixNe123456"
        browser = self.browser(appdir / "usr/bin/epix-browser")
        outer = self.appimage(self.root / "Applications/EpixNet.AppImage")
        non_executable = self.appimage(self.root / "Applications/NoExecute.AppImage")
        non_executable.chmod(0o644)
        directory = self.root / "Applications/Directory.AppImage"
        directory.mkdir()
        newline = self.appimage(self.root / "Applications/Line\nBreak.AppImage")
        tab = self.appimage(self.root / "Applications/Tab\tName.AppImage")
        non_utf8 = self.appimage(self.root / "Applications" / os.fsdecode(b"Bad-\xff.AppImage"))
        self.env["APPDIR"] = str(appdir)
        self.desktop.parent.mkdir(parents=True)
        original = b"[Desktop Entry]\nType=Application\nName=Existing entry\nExec=/bin/true\n"
        for candidate in (
            "", str(outer.relative_to(self.root)), str(self.root / "missing.AppImage"),
            str(non_executable), str(directory), str(newline), str(tab), str(non_utf8),
        ):
            with self.subTest(path=candidate):
                self.desktop.write_bytes(original)
                self.env["APPIMAGE"] = candidate
                result = self.run_browser(browser, "enable", check=False)
                self.assertNotEqual(result.returncode, 0, "Invalid AppImage path was accepted")
                self.assertEqual(self.desktop.read_bytes(), original)

    def test_invalid_native_path_leaves_existing_entry_untouched(self):
        self.desktop.parent.mkdir(parents=True)
        original = b"Existing autostart configuration\n"
        for name in ("Line\nBreak", "Tab\tName", os.fsdecode(b"Bad-\xff")):
            with self.subTest(name=name):
                browser = self.browser(self.root / name / "epix-browser")
                self.desktop.write_bytes(original)
                result = self.run_browser(browser, "enable", check=False)
                self.assertNotEqual(result.returncode, 0, "Invalid native executable path was accepted")
                self.assertEqual(self.desktop.read_bytes(), original)

    def test_extracted_appimage_preserves_extraction_mode_at_login(self):
        self.enable_appimage(appdir_name="appimage_extracted_" + "a" * 32)
        self.env.pop("APPIMAGE", None)
        self.env.pop("APPDIR", None)
        self.launch("appimage")
        self.assertEqual(self.mode.read_text(), "1")

    def test_explicit_extract_and_run_survives_a_fresh_login_environment(self):
        for value in ("1", "0", ""):
            with self.subTest(value=value):
                self.env["APPIMAGE_EXTRACT_AND_RUN"] = value
                self.enable_appimage()
                for name in ("APPIMAGE", "APPDIR", "APPIMAGE_EXTRACT_AND_RUN"):
                    self.env.pop(name, None)
                self.launch("appimage")
                self.assertEqual(self.mode.read_text(), "1")
                self.capture.unlink()

    @staticmethod
    def legacy_entry(executable):
        return (
            "[Desktop Entry]\nType=Application\nName=EpixNet\n"
            f'Exec="{executable}" --background\n'
            "Terminal=false\nX-GNOME-Autostart-enabled=true\n"
        )

    def test_refresh_repairs_old_appimage_entries_and_survives_unmount(self):
        for name, expected_mode in (
            (".mount_EpixNe123456", ""),
            ("appimage_extracted_" + "a" * 32, "1"),
        ):
            with self.subTest(appdir=name):
                appdir = self.root / "current-session" / name
                browser = self.browser(appdir / "usr/bin/epix-browser")
                outer = self.appimage(self.root / "Applications/New EpixNet.AppImage")
                self.env.update(APPDIR=str(appdir), APPIMAGE=str(outer))
                old_browser = self.root / "previous-session" / name / "usr/bin/epix-browser"
                self.assertFalse(old_browser.exists())
                old_entry = self.legacy_entry(old_browser)
                self.desktop.parent.mkdir(parents=True, exist_ok=True)
                self.desktop.write_text(old_entry)
                self.run_browser(browser, "refresh")
                self.assertNotEqual(self.desktop.read_text(), old_entry)
                self.assertEqual(self.run_browser(browser, "status").stdout.strip(), "true")
                shutil.rmtree(appdir)
                self.launch("appimage")
                self.assertEqual(self.mode.read_text(), expected_mode)
                self.capture.unlink()

    def test_refresh_preserves_missing_and_customized_entries(self):
        appdir = self.root / ".mount_EpixNe123456"
        browser = self.browser(appdir / "usr/bin/epix-browser")
        outer = self.appimage(self.root / "Applications/EpixNet.AppImage")
        self.env.update(APPDIR=str(appdir), APPIMAGE=str(outer))
        self.run_browser(browser, "refresh")
        self.assertFalse(self.desktop.exists(), "Refresh enabled a missing login item")
        old_browser = self.root / ".mount_Previous123456/usr/bin/epix-browser"
        legacy = self.legacy_entry(old_browser)
        self.desktop.parent.mkdir(parents=True)
        cases = {
            "hidden": legacy + "Hidden=true\n",
            "disabled": legacy.replace("Autostart-enabled=true", "Autostart-enabled=false"),
            "extra argument": legacy.replace(" --background\n", " --background --custom\n"),
            "extra key": legacy + "OnlyShowIn=GNOME;\n",
            "comment": "# User configuration\n" + legacy,
            "native executable": self.legacy_entry(self.root / "native/usr/bin/epix-browser"),
            "relative executable": self.legacy_entry(".mount_Previous123456/usr/bin/epix-browser"),
            "quoted pathname": self.legacy_entry(self.root / '.mount_Previous"Quote/usr/bin/epix-browser'),
            "newline pathname": self.legacy_entry(self.root / ".mount_Previous\nLine/usr/bin/epix-browser"),
            "tab pathname": self.legacy_entry(self.root / ".mount_Previous\tTab/usr/bin/epix-browser"),
        }
        for description, content in cases.items():
            with self.subTest(entry=description):
                self.desktop.write_text(content)
                os.utime(self.desktop, ns=(1_000_000_000, 1_000_000_000))
                before = self.desktop.stat()
                self.run_browser(browser, "refresh")
                self.assertEqual(self.desktop.read_text(), content)
                self.assertEqual(self.desktop.stat().st_mtime_ns, before.st_mtime_ns)

    def test_refresh_does_not_rewrite_new_entries(self):
        appdir = self.root / ".mount_EpixNe123456"
        browser = self.browser(appdir / "usr/bin/epix-browser")
        outer = self.appimage(self.root / "Applications/EpixNet.AppImage")
        self.env.update(APPDIR=str(appdir), APPIMAGE=str(outer))
        self.run_browser(browser, "enable")
        original = self.desktop.read_bytes()
        os.utime(self.desktop, ns=(1_000_000_000, 1_000_000_000))
        before = self.desktop.stat()
        self.env["APPIMAGE"] = str(self.root / "missing.AppImage")
        self.run_browser(browser, "refresh")
        self.assertEqual(self.desktop.read_bytes(), original)
        self.assertEqual(self.desktop.stat().st_mtime_ns, before.st_mtime_ns)

    def test_refresh_preserves_symlinked_entries_and_their_targets(self):
        browser = self.browser(self.root / "native/epix-browser")
        old_browser = self.root / ".mount_Previous123456/usr/bin/epix-browser"
        original = self.legacy_entry(old_browser)
        target = self.root / "managed-entry.desktop"
        target.write_text(original)
        os.utime(target, ns=(1_000_000_000, 1_000_000_000))
        before = target.stat()
        self.desktop.parent.mkdir(parents=True)
        self.desktop.symlink_to(target)
        self.run_browser(browser, "refresh")
        self.assertTrue(self.desktop.is_symlink())
        self.assertEqual(self.desktop.readlink(), target)
        self.assertEqual(target.read_text(), original)
        self.assertEqual(target.stat().st_mtime_ns, before.st_mtime_ns)
        target.unlink()
        self.run_browser(browser, "refresh")
        self.assertTrue(self.desktop.is_symlink())
        self.assertFalse(target.exists(), "Refresh recreated a broken symlink target")


if __name__ == "__main__":
    unittest.main()
