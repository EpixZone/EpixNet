#!/usr/bin/env python3
"""Check the EpixNet Portable zip built from a staged Windows tree."""

import importlib.util
import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("make_portable", HERE / "make-portable.py")
make_portable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make_portable)

STAGED_POLICIES = {
    "policies": {
        "Certificates": {"Install": ["epix-ca.pem"]},
        "SearchEngines": {"Default": "DuckDuckGo"},
    }
}


class PortableZipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="epix-portable-")
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name) / "epix-windows"
        for name in ("epix-browser.exe", "epix-nmh.exe", "evx-worker.exe",
                     "epix_snowflake-x86_64-pc-windows-msvc.dll", "firefox/firefox.exe",
                     "firefox/xul.dll", "firefox/distribution/epix-addon-installer/addon.js"):
            path = self.stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        (self.stage / make_portable.POLICIES).write_text(json.dumps(STAGED_POLICIES))
        self.out = Path(self.temp.name) / "dist/EpixNet-Portable-1.2.3-x64.zip"

    def test_zip_has_one_folder_with_the_stage_marker_and_portable_policies(self):
        make_portable.pack(self.stage, self.out)
        with zipfile.ZipFile(self.out) as archive:
            names = archive.namelist()
            self.assertTrue(all(name.startswith("EpixNet Portable/") for name in names), names)
            self.assertEqual(len(names), len(set(names)))
            for name in ("epix-browser.exe", "firefox/xul.dll",
                         "firefox/distribution/epix-addon-installer/addon.js"):
                self.assertEqual(archive.read(f"EpixNet Portable/{name}"), name.encode())
            policies = json.loads(archive.read(f"EpixNet Portable/{make_portable.POLICIES}"))
            self.assertEqual(policies["policies"], {
                "SearchEngines": {"Default": "DuckDuckGo"},
                "DisableAppUpdate": True,
            })
            marker = archive.read("EpixNet Portable/epixnet-portable.txt").decode()
            self.assertIn("epix-browser.exe", marker)
            self.assertIn("\r\n", marker)
            self.assertFalse(any("/Data/" in name for name in names))
        # The stage itself stays the installer's: same policies, no marker.
        self.assertEqual(json.loads((self.stage / make_portable.POLICIES).read_text()),
                         STAGED_POLICIES)
        self.assertFalse((self.stage / make_portable.MARKER).exists())
        self.assertFalse(self.out.with_name(self.out.name + ".partial").exists())

    def test_incomplete_or_reused_stage_is_refused(self):
        (self.stage / "evx-worker.exe").unlink()
        with self.assertRaises(SystemExit):
            make_portable.pack(self.stage, self.out)
        (self.stage / "evx-worker.exe").write_bytes(b"worker")
        (self.stage / make_portable.MARKER).write_text("portable")
        with self.assertRaises(SystemExit):
            make_portable.pack(self.stage, self.out)
        self.assertFalse(self.out.exists())

    def test_marker_name_matches_the_launcher(self):
        source = (ROOT / "crates/epix-ui/src/paths.rs").read_text(encoding="utf-8")
        match = re.search(r'pub const PORTABLE_MARKER: &str = "([^"]+)";', source)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), make_portable.MARKER)
        data = re.search(r'pub const PORTABLE_DATA_DIR: &str = "([^"]+)";', source)
        self.assertEqual(data.group(1), "Data")


if __name__ == "__main__":
    unittest.main()
