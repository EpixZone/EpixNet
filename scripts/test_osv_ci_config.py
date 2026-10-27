#!/usr/bin/env python3
"""Check that the temporary OSV exception cannot cover unverified crates."""

from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


SCRIPT = Path(__file__).with_name("osv_ci_config.py")
ADVISORY = "GHSA-qwgh-2vcv-g2f7"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
BEFORE_EXPIRY = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
EXPIRY = datetime(2026, 11, 3, tzinfo=timezone.utc)
# These fixtures are independent of the generator's allowlist.
CHECKSUMS = {
    "0.9.0": "4152116fd6e9dadb291ae18fc1ec3575ed6d84c29642d97890f4b4a3417297e4",
    "0.10.4": "3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71",
    "0.12.1": "d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa",
}
BASE_CONFIG = '''# Existing accepted policy must survive unchanged.
[[IgnoredVulns]]
id = "RUSTSEC-2023-0071"
reason = "Existing reviewed exception."

[[IgnoredVulns]]
id = "GHSA-test-existing-policy"
ignoreUntil = 2027-01-01T00:00:00Z
reason = "A separate existing exception."

[[PackageOverrides]]
name = "unrelated-package"
ecosystem = "crates.io"
version = "1.0.0"
license.override = ["MIT"]
reason = "Existing license policy."
'''


def package(version="0.9.0", **changes):
    entry = {
        "name": "block-buffer",
        "version": version,
        "source": REGISTRY,
        "checksum": CHECKSUMS.get(version, "0" * 64),
    }
    entry.update(changes)
    return entry


def lockfile(*packages):
    lines = ["version = 4", ""]
    for entry in packages:
        lines.append("[[package]]")
        lines.extend(f"{key} = {json.dumps(value)}" for key, value in entry.items())
        lines.append("")
    return "\n".join(lines)


class ConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("osv_ci_config", SCRIPT)
        cls.helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.helper
        spec.loader.exec_module(cls.helper)

    def build(self, inventory, now=BEFORE_EXPIRY, base=BASE_CONFIG):
        return self.helper.build_config(base, inventory, now)

    def assert_exception(self, result, base=BASE_CONFIG):
        self.assertTrue(result.startswith(base), "Existing text was rewritten")
        parsed = tomllib.loads(result)
        original = tomllib.loads(base)
        ignores = parsed["IgnoredVulns"]
        existing = original.get("IgnoredVulns", [])
        self.assertEqual(ignores[:-1], existing)
        self.assertEqual(ignores[-1]["id"], ADVISORY)
        self.assertEqual(ignores[-1]["ignoreUntil"], EXPIRY)
        self.assertEqual(sum(item["id"] == ADVISORY for item in ignores), 1)
        if "IgnoredVulns" in original:
            parsed["IgnoredVulns"] = ignores[:-1]
        else:
            del parsed["IgnoredVulns"]
        self.assertEqual(parsed, original, "Unrelated scanner policy changed")

    def test_verified_legacy_versions_get_only_expiring_advisory_exception(self):
        cases = [
            [package("0.9.0")],
            [package("0.10.4")],
            [package("0.9.0"), package("0.10.4"), package("0.12.1")],
            [package("0.12.1"), package("0.9.0")],
        ]
        for entries in cases:
            with self.subTest(versions=[entry["version"] for entry in entries]):
                self.assert_exception(self.build(lockfile(*entries)))

    def test_empty_config_and_config_without_final_newline_remain_valid(self):
        for base in ("", BASE_CONFIG.rstrip("\n")):
            with self.subTest(base=base):
                self.assert_exception(self.build(lockfile(package()), base=base), base)

    def test_unrelated_packages_do_not_change_existing_policy(self):
        inventory = lockfile(
            {"name": "local-workspace-crate", "version": "0.1.0"},
            package("0.10.4"),
            {"name": "other-crate", "version": "9.8.7", "source": REGISTRY,
             "checksum": "1" * 64},
        )
        self.assert_exception(self.build(inventory))

    def test_patched_only_and_no_block_buffer_leave_original_config_unchanged(self):
        for entries in (
            [package("0.12.1")],
            [{"name": "unrelated-package", "version": "1.0.0"}],
        ):
            with self.subTest(entries=entries):
                self.assertEqual(self.build(lockfile(*entries)), BASE_CONFIG)

    def test_affected_and_unknown_versions_disable_exception_for_entire_scan(self):
        for version in ("0.11.0", "0.12.0", "0.12.2", "0.13.0", "0.10.3",
                        "0.10.4+custom", "0.9.0-beta.1"):
            with self.subTest(version=version):
                self.assertEqual(
                    self.build(lockfile(package(), package(version))), BASE_CONFIG
                )

    def test_unverified_sources_disable_exception_even_for_patched_version(self):
        sources = (
            "git+https://example.invalid/block-buffer#deadbeef",
            "registry+https://example.invalid/index",
            "sparse+https://index.crates.io/",
            "",
        )
        for version in ("0.10.4", "0.12.1"):
            for source in sources:
                with self.subTest(version=version, source=source):
                    inventory = lockfile(package(), package(version, source=source))
                    self.assertEqual(self.build(inventory), BASE_CONFIG)

    def test_missing_source_or_checksum_disables_exception(self):
        for key in ("source", "checksum"):
            changed = package("0.10.4")
            del changed[key]
            with self.subTest(key=key):
                self.assertEqual(self.build(lockfile(package(), changed)), BASE_CONFIG)

    def test_wrong_or_mismatched_checksum_disables_exception(self):
        for version in ("0.10.4", "0.12.1"):
            for checksum in ("", "0" * 64, CHECKSUMS["0.9.0"],
                             CHECKSUMS[version].upper()):
                with self.subTest(version=version, checksum=checksum):
                    changed = package(version, checksum=checksum)
                    self.assertEqual(self.build(lockfile(package(), changed)), BASE_CONFIG)

    def test_case_and_underscore_variants_cannot_bypass_inventory_guard(self):
        for name in ("block_buffer", "Block-Buffer", "BLOCK_BUFFER", "BLOCK-BUFFER"):
            for version in ("0.10.4", "0.11.0"):
                with self.subTest(name=name, version=version):
                    changed = package(version, name=name)
                    self.assertEqual(self.build(lockfile(package(), changed)), BASE_CONFIG)

    def test_duplicate_versions_disable_exception(self):
        for version in ("0.9.0", "0.10.4", "0.12.1"):
            with self.subTest(version=version):
                entries = [package(version), package(version)]
                if version != "0.9.0":
                    entries.append(package())
                self.assertEqual(self.build(lockfile(*entries)), BASE_CONFIG)

    def test_expiry_boundary_and_timezone_are_enforced(self):
        inventory = lockfile(package())
        self.assert_exception(self.build(inventory, now=EXPIRY - timedelta(microseconds=1)))
        for now in (EXPIRY, EXPIRY + timedelta(microseconds=1),
                    EXPIRY.astimezone(timezone(timedelta(hours=-7)))):
            with self.subTest(now=now):
                self.assertEqual(self.build(inventory, now=now), BASE_CONFIG)

    def test_existing_exception_is_rejected_instead_of_reused_or_duplicated(self):
        existing = BASE_CONFIG + f'\n[[IgnoredVulns]]\nid = "{ADVISORY}"\n'
        for now in (BEFORE_EXPIRY, EXPIRY):
            with self.subTest(now=now):
                with self.assertRaises(ValueError):
                    self.build(lockfile(package()), now=now, base=existing)

    def test_malformed_toml_inputs_are_rejected(self):
        for base, inventory in (
            ("[[IgnoredVulns]\n", lockfile(package())),
            (BASE_CONFIG, '[[package]]\nname = "unterminated\n'),
            (BASE_CONFIG, 'version = 4\nversion = 3\n'),
        ):
            with self.subTest(base=base, inventory=inventory):
                with self.assertRaises(ValueError):
                    self.build(inventory, base=base)

    def test_missing_or_empty_package_inventory_is_rejected(self):
        for inventory in ("", "version = 4\n", "version = 4\npackage = []\n"):
            with self.subTest(inventory=inventory):
                with self.assertRaises(ValueError):
                    self.build(inventory)


class CommandTests(unittest.TestCase):
    def run_cli(self, root):
        return subprocess.run(
            [sys.executable, str(SCRIPT)], cwd=root, capture_output=True,
            text=True, timeout=10, check=False,
        )

    def test_cli_writes_generated_config_without_changing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Patched-only input keeps this test independent of the wall clock.
            inventory = lockfile(package("0.12.1"))
            (root / "Cargo.lock").write_text(inventory)
            (root / "osv-scanner.toml").write_text(BASE_CONFIG)
            result = self.run_cli(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / ".osv-scanner-ci.toml").read_text(), BASE_CONFIG)
            self.assertEqual((root / "Cargo.lock").read_text(), inventory)
            self.assertEqual((root / "osv-scanner.toml").read_text(), BASE_CONFIG)

    def test_cli_missing_or_malformed_inputs_fail_without_output(self):
        for bad_file in ("Cargo.lock", "osv-scanner.toml"):
            for mode in ("missing", "malformed"):
                with self.subTest(file=bad_file, mode=mode):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / "Cargo.lock").write_text(lockfile(package()))
                        (root / "osv-scanner.toml").write_text(BASE_CONFIG)
                        if mode == "missing":
                            (root / bad_file).unlink()
                        else:
                            (root / bad_file).write_text('key = "unterminated\n')
                        result = self.run_cli(root)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse((root / ".osv-scanner-ci.toml").exists())


if __name__ == "__main__":
    unittest.main()
