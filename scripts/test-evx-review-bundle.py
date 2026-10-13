#!/usr/bin/env python3
"""Disposable source-export regressions; no build tools, credentials or network."""

import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


spec = importlib.util.spec_from_file_location("review_bundle", Path(__file__).with_name("evx-review-bundle.py"))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class ReviewBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.git("init", "--quiet")
        self.write("Cargo.toml", "[workspace]\n")
        self.write("crates/evx-api/src/lib.rs", "pub const SCORE: u32 = 1;\n")
        self.write("docs/evx.md", "Review fixture\n")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "Fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def save(self, data):
        path = Path(self.temp.name) / "review.zip"
        path.write_bytes(data)
        return path

    def test_default_excludes_untracked_credentials_artifacts_and_unrelated_source(self):
        for name in [".env", "crates/evx-api/src/private.key", "fuzz/results/run.log", "target/evx-worker", "crates/unrelated/src/lib.rs"]:
            self.write(name, "fixture must not be exported\n")
            self.git("add", "--", name)
        self.write("crates/evx-api/src/new.rs", "// explicit selection required\n")
        manifest, blobs = bundle.snapshot(self.root)
        self.assertEqual(set(blobs), {"Cargo.toml", "crates/evx-api/src/lib.rs", "docs/evx.md"})
        self.assertEqual(manifest["omitted_untracked_sources"], ["crates/evx-api/src/new.rs"])
        self.assertNotIn(str(self.root).encode(), bundle.encode(manifest, blobs))

    def test_explicit_source_selection_changes_and_deletion_round_trip(self):
        self.write("crates/evx-api/src/lib.rs", "pub const SCORE: u32 = 2;\n")
        self.write("crates/evx-api/src/new.rs", "// new reviewed source\n")
        (self.root / "docs/evx.md").unlink()
        first = bundle.snapshot(self.root, ["crates/evx-api/src/new.rs"])
        second = bundle.snapshot(self.root, ["crates/evx-api/src/new.rs"])
        encoded = bundle.encode(*first)
        self.assertEqual(encoded, bundle.encode(*second))
        self.assertEqual(bundle.verify(self.save(encoded)), first[0])
        states = {r["path"]: r["status"] for r in first[0]["files"]}
        self.assertEqual(states["Cargo.toml"], "unchanged")
        self.assertEqual(states["crates/evx-api/src/lib.rs"], "modified")
        self.assertEqual(states["crates/evx-api/src/new.rs"], "added")
        self.assertEqual(states["docs/evx.md"], "deleted")

    def test_cannot_select_ignored_or_out_of_scope_files(self):
        self.write(".gitignore", "crates/evx-api/src/ignored.rs\n")
        self.write("crates/evx-api/src/ignored.rs", "// ignored\n")
        self.write("private.key", "fixture\n")
        for name in ["private.key", "crates/evx-api/src/ignored.rs", "../outside.rs", "/tmp/outside.rs", "docs/../docs/evx.md"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                bundle.snapshot(self.root, [name])

    def test_mobile_scope_contains_sources_without_sdk_or_build_outputs(self):
        for name in ["packaging/android/evx-fixture/src/zone/epix/GameService.java",
                     "packaging/android/evx-fixture/sdk-provenance.json",
                     "packaging/ios/evx-fixture/Shared/GameProtocol.swift",
                     "packaging/ios/evx-fixture/Helper.xcconfig"]:
            self.assertTrue(bundle.eligible(name), name)
        for name in ["packaging/android/evx-fixture/android.jar",
                     "packaging/android/evx-fixture/build/AndroidManifest.xml",
                     "packaging/android/evx-fixture/src/release.keystore",
                     "packaging/ios/evx-fixture/DerivedData/Info.plist",
                     "packaging/ios/evx-fixture/signing.json"]:
            self.assertFalse(bundle.eligible(name), name)

    def test_staged_deletion_remains_in_the_overlay(self):
        self.git("rm", "--", "docs/evx.md")
        manifest, blobs = bundle.snapshot(self.root)
        states = {record["path"]: record["status"] for record in manifest["files"]}
        self.assertEqual(states.get("docs/evx.md"), "deleted")
        self.assertNotIn("docs/evx.md", blobs)

    def test_manifest_preserves_executable_mode_without_executable_zip_members(self):
        script = self.write("scripts/check-evx-platforms.py", "#!/usr/bin/env python3\n")
        script.chmod(0o755)
        self.git("add", "--", "scripts/check-evx-platforms.py")
        manifest, blobs = bundle.snapshot(self.root)
        modes = {record["path"]: record.get("mode") for record in manifest["files"]}
        self.assertEqual(modes["scripts/check-evx-platforms.py"], "100755")
        self.assertEqual(modes["docs/evx.md"], "100644")
        encoded = bundle.encode(manifest, blobs)
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            self.assertEqual(archive.getinfo("source/scripts/check-evx-platforms.py").external_attr >> 16, 0o100644)
        self.assertEqual(bundle.verify(self.save(encoded)), manifest)

    def test_symlinked_source_and_parent_are_refused(self):
        source = self.root / "crates/evx-api/src/lib.rs"
        source.unlink()
        source.symlink_to(self.root / "docs/evx.md")
        with self.assertRaisesRegex(ValueError, "symlink"):
            bundle.snapshot(self.root)
        source.unlink()
        source.parent.rmdir()
        source.parent.symlink_to(self.root / "docs", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            bundle.snapshot(self.root)

    def test_binary_and_oversized_sources_are_refused(self):
        path = self.root / "crates/evx-api/src/lib.rs"
        path.write_bytes(b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            bundle.snapshot(self.root)
        path.write_text("x" * 65)
        with patch.object(bundle, "MAX_FILE", 64), self.assertRaisesRegex(ValueError, "oversized"):
            bundle.snapshot(self.root)

    def test_tampered_source_fails_hash_check(self):
        manifest, blobs = bundle.snapshot(self.root)
        blobs["docs/evx.md"] = b"Changed bytes\n"
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            bundle.verify(self.save(bundle.encode(manifest, blobs)))

    def test_extra_entry_and_manifest_path_traversal_are_refused(self):
        manifest, blobs = bundle.snapshot(self.root)
        blobs["unexpected.rs"] = b"// not in inventory\n"
        with self.assertRaisesRegex(ValueError, "inventory"):
            bundle.verify(self.save(bundle.encode(manifest, blobs)))
        manifest["files"][0]["path"] = "../outside"
        with self.assertRaisesRegex(ValueError, "source path"):
            bundle.verify(self.save(bundle.encode(manifest, {})))

    def test_verify_bounds_uncompressed_data_before_reading(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", " " * 65)
        with patch.object(bundle, "MAX_FILE", 64), self.assertRaisesRegex(ValueError, "uncompressed"):
            bundle.verify(self.save(data.getvalue()))

    def test_export_does_not_overwrite_or_write_inside_repository(self):
        output = Path(self.temp.name) / "review.zip"
        output.write_bytes(b"existing evidence")
        with patch.object(bundle, "ROOT", self.root), patch("sys.argv", ["bundle", "--output", str(output)]), self.assertRaises(SystemExit):
            bundle.main()
        self.assertEqual(output.read_bytes(), b"existing evidence")
        with patch.object(bundle, "ROOT", self.root), patch("sys.argv", ["bundle", "--output", str(self.root / "review.zip")]), self.assertRaises(SystemExit):
            bundle.main()
        self.assertFalse((self.root / "review.zip").exists())


if __name__ == "__main__":
    unittest.main()
