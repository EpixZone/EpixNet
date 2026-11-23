#!/usr/bin/env python3
import json
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare
import sign
import rebuild


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "epixnet"
        self.wallet = self.root / "wallet"
        for path in (self.repo, self.wallet):
            path.mkdir()
            subprocess.run(["git", "init", "-q", str(path)], check=True)
        (self.wallet / "source.js").write_text("// human-readable wallet source\n")
        (self.wallet / "package.json").write_text(json.dumps({"packageManager": "yarn@3.4.1"}))
        self.wallet_revision = self.commit(self.wallet)
        self.review = json.loads((HERE / "data-disclosure.json").read_text())
        self.review["wallet_revision"] = self.wallet_revision
        self.review_path = self.repo / "packaging/firefox-wallet/data-disclosure.json"
        self.review_path.parent.mkdir(parents=True)
        self.review["build_tools"].update(node="22.9.1", protoc="25.4", release_run=12345)
        (self.review_path.parent / "REVIEWER.txt").write_bytes((HERE / "REVIEWER.txt").read_bytes())
        self.review_path.write_text(json.dumps(self.review))
        (self.repo / "shells").mkdir()
        (self.repo / "shells/wallet-ext.rev").write_text(self.wallet_revision[:12])
        self.archive = self.root / "wallet.zip"
        self.entries = {"manifest.json": json.dumps({"manifest_version": 2, "version": "1.0.0",
            "applications": {"gecko": {"id": prepare.WALLET_ID}}, "incognito": "spanning"}).encode(),
            "background.js": b"// final wallet code",
            "epix-mobile-build.json": json.dumps({"revision": self.wallet_revision, "modifiedSource": False,
                "analyticsConfigured": False, "termsURL": "https://example.com/terms/", "privacyURL": "https://example.com/privacy/"}).encode()}
        prepare.write_archive(self.archive, self.entries)
        (self.repo / "shells/wallet-ext.sha256").write_text(prepare.sha256(self.archive.read_bytes()) + " wallet.zip\n")
        self.revision = self.commit(self.repo)
        self.browser = self.root / "browser"
        metadata = {"source_revision": self.revision[:12], "wallet_revision": self.wallet_revision[:12],
                    "wallet_source_sha256": prepare.source_fingerprint(self.entries),
                    "archive_sha256": prepare.sha256(self.archive.read_bytes())}
        self.browser.write_text(f"#!{sys.executable}\nimport json,shutil,sys\nshutil.copyfile({str(self.archive)!r},sys.argv[2])\nprint({json.dumps(metadata)!r})\n")
        self.browser.chmod(0o755)
        self.args = SimpleNamespace(browser=self.browser, wallet_source=self.wallet, wallet_archive=self.archive,
            version="1.0.0.1", output=self.root / "prepared")

    def commit(self, path):
        subprocess.run(["git", "-C", str(path), "add", "."], check=True)
        subprocess.run(["git", "-C", str(path), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-qm", "Fixture source"], check=True)
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()

    def test_prepare_keeps_payload_permissions_and_matching_source(self):
        receipt = prepare.prepare(self.args, self.repo)
        entries = sign.checked_preparation(self.args.output)
        self.assertEqual(entries["background.js"], self.entries["background.js"])
        manifest = json.loads(entries["manifest.json"])
        self.assertEqual(manifest["version"], self.args.version)
        self.assertEqual(manifest["incognito"], "spanning")
        self.assertNotIn("applications", manifest)
        self.assertEqual(manifest["browser_specific_settings"], {"gecko": {
            "id": prepare.WALLET_ID, **self.review["gecko"]}})
        self.assertEqual(receipt["epixnet_revision"], self.revision)
        self.assertEqual(receipt["wallet_revision"], self.wallet_revision)
        source = prepare.read_archive(self.args.output / "source.zip")
        self.assertIn("epix-wallet/source.js", source)
        self.assertIn(b"1.0.0.1", source["BUILD.txt"])
        self.assertIn(b"Node 22.9.1, the included Yarn 3.4.1 and protoc 25.4", source["BUILD.txt"])
        self.assertIn(b"/actions/runs/12345", source["BUILD.txt"])
        notes = source["REVIEWER.txt"].decode()
        self.assertIn(f"/epix-wallet/tree/{self.wallet_revision}", notes)
        self.assertIn(f"/EpixNet/tree/{self.revision}", notes)
        self.assertIn("https://example.com/privacy/", notes)
        self.assertIn("https://example.com/terms/", notes)
        with self.assertRaises(FileExistsError):
            prepare.prepare(self.args, self.repo)

    def test_source_bundle_restores_exact_clean_git_metadata(self):
        prepare.prepare(self.args, self.repo)
        unpacked = self.root / "source"
        with zipfile.ZipFile(self.args.output / "source.zip") as archive:
            archive.extractall(unpacked)
        metadata = json.loads((unpacked / "SOURCE.json").read_text())
        rebuild.restore(unpacked, metadata)
        for name, revision in (("EpixNet", self.revision), ("epix-wallet", self.wallet_revision)):
            self.assertEqual(rebuild.git(unpacked / name, "rev-parse", "HEAD"), revision)
            self.assertEqual(rebuild.git(unpacked / name, "status", "--porcelain"), "")
        self.assertEqual(metadata["environment"]["EPIX_TERMS_URL"], "https://example.com/terms/")
        self.assertIn(b"EPIX_MOBILE_STORE_BUILD=1", (unpacked / "wallet-build-env.sh").read_bytes())
        rebuild.verify(self.entries, metadata["wallet_files"])
        subprocess.run([sys.executable, unpacked / "rebuild.py", "verify-final", self.archive], check=True)
        with self.assertRaisesRegex(ValueError, "differs"):
            rebuild.verify({**self.entries, "background.js": b"changed"}, metadata["wallet_files"])
        with self.assertRaisesRegex(ValueError, "newly extracted"):
            rebuild.restore(unpacked, metadata)

    def test_submission_preserves_all_browser_settings_and_rejects_conflicting_aliases(self):
        settings = {"gecko": {"id": prepare.WALLET_ID, "strict_min_version": "102.0",
                              "strict_max_version": "160.*"}, "safari": {"strict_min_version": "16"}}
        expected = {"browser_specific_settings": {"gecko": {**settings["gecko"], **self.review["gecko"]},
                                                  "safari": settings["safari"]}, "version": "2"}
        for manifest in ({"applications": settings}, {"browser_specific_settings": settings},
                         {"applications": settings, "browser_specific_settings": settings}):
            self.assertEqual(json.loads(rebuild.submission_manifest(manifest, "2", self.review["gecko"])), expected)
        with self.assertRaisesRegex(ValueError, "conflicting browser settings"):
            rebuild.submission_manifest({"applications": settings, "browser_specific_settings": {}}, "2", self.review["gecko"])

    def test_source_recipe_rejects_unmatched_package_manager(self):
        self.review["build_tools"]["yarn"] = "3.9.0"
        self.review_path.write_text(json.dumps(self.review))
        updated = self.commit(self.repo)
        self.browser.write_text(self.browser.read_text().replace(self.revision[:12], updated[:12]))
        with self.assertRaisesRegex(ValueError, "Yarn version differs"):
            prepare.prepare(self.args, self.repo)

    def test_unreviewed_wallet_pin_stops_preparation(self):
        self.review["wallet_revision"] = "0" * 40
        self.review_path.write_text(json.dumps(self.review))
        self.commit(self.repo)
        with self.assertRaisesRegex(ValueError, "Review the data disclosure"):
            prepare.prepare(self.args, self.repo)
        self.assertFalse(self.args.output.exists())

    def test_lint_warnings_block_submission_and_are_retained(self):
        prepare.prepare(self.args, self.repo)
        report = {"summary": {"errors": 0, "warnings": 1}, "warnings": [{"code": "DANGEROUS_EVAL"}]}
        completed = SimpleNamespace(stdout=json.dumps(report), returncode=1)
        with patch.object(sign, "pinned_cli", return_value="web-ext"), \
                patch.object(sign.subprocess, "run", return_value=completed) as command, \
                patch.dict(os.environ, {"WEB_EXT_API_KEY": "fixture", "WEB_EXT_API_SECRET": "fixture"}):
            with self.assertRaisesRegex(ValueError, "Submission was not attempted"):
                sign.sign(self.args.output, self.root / "returned")
        command.assert_called_once()
        self.assertEqual(json.loads((self.args.output / "lint.json").read_text()), report)
        self.assertFalse((self.root / "returned").exists())

    def reviewed_fixture(self):
        receipt = prepare.prepare(self.args, self.repo)
        review = json.loads(sign.REVIEW_FILE.read_text())
        for finding in review["findings"]:
            finding["diagnostic"]["file"] = "background.js"
            finding["bundle_sha256"] = prepare.sha256(self.entries["background.js"])
        for key in ("wallet_revision", "version", "unsigned_sha256"):
            review[key] = receipt[key]
        path = self.root / "fixture-review.json"
        path.write_text(json.dumps(review))
        fixture = patch.object(sign, "REVIEW_FILE", path)
        fixture.start()
        self.addCleanup(fixture.stop)
        diagnostics = [row["diagnostic"] for row in reversed(review["findings"])]
        return {"metadata": {"id": review["extension_id"], "version": receipt["version"]},
                "summary": {"warnings": len(diagnostics), "errors": 0, "notices": 0},
                "count": len(diagnostics), "warnings": diagnostics, "errors": [], "notices": []}

    def test_reviewed_submission_sends_original_report_source_instructions_and_notes(self):
        report = self.reviewed_fixture()
        raw = json.dumps(report, indent=1) + "\n"
        output = self.root / "returned"
        expected = sign.checked_preparation(self.args.output)

        def service(command, check, **kwargs):
            if "lint" in command:
                self.assertIn("--warnings-as-errors", command)
                return SimpleNamespace(stdout=raw, returncode=1)
            self.assertTrue(check)
            self.assertIn("--channel=unlisted", command)
            source = prepare.read_archive(Path(command[command.index("--upload-source-code") + 1]))
            self.assertEqual(source["mozilla-lint.json"], raw.encode())
            self.assertEqual(source["reviewed-findings.json"], sign.REVIEW_FILE.read_bytes())
            self.assertIn("epix-wallet/source.js", source)
            self.assertIn("EpixNet/shells/wallet-ext.rev", source)
            self.assertIn(b"rebuild.py verify-final", source["BUILD.txt"])
            metadata = json.loads(Path(command[command.index("--amo-metadata") + 1]).read_text())
            self.assertIn("mozilla-lint.json", metadata["version"]["approval_notes"])
            prepare.write_archive(output / "wallet.xpi", expected)

        with patch.object(sign, "pinned_cli", return_value="web-ext"), \
                patch.object(sign.subprocess, "run", side_effect=service) as command, \
                patch.dict(os.environ, {"WEB_EXT_API_KEY": "fixture", "WEB_EXT_API_SECRET": "fixture"}):
            with self.assertRaisesRegex(ValueError, "not attempted"):
                sign.sign(self.args.output, output)
            self.assertFalse(output.exists())
            receipt = sign.sign(self.args.output, output, reviewed_warnings=True)
        self.assertEqual(command.call_count, 3)
        self.assertFalse(receipt["firefox_signature_verified"])

    def test_review_rejects_changes_to_diagnostics_candidate_or_lint_status(self):
        report = self.reviewed_fixture()
        candidate = sign.checked_preparation(self.args.output)
        for field in ("code", "message", "file", "line", "column", "description", "_type"):
            with self.subTest(field=field):
                changed = deepcopy(report)
                changed["warnings"][0][field] = "different"
                with self.assertRaisesRegex(ValueError, "diagnostics differ"):
                    sign.verify_review(self.args.output, candidate, changed, 1)
        for warnings in (report["warnings"][:-1], report["warnings"] + report["warnings"][:1],
                         [report["warnings"][1], *report["warnings"][1:]]):
            with self.assertRaisesRegex(ValueError, "diagnostics differ"):
                sign.verify_review(self.args.output, candidate, {**report, "warnings": warnings}, 1)
        for change in ({"errors": [{}]}, {"notices": [{}]}, {"count": 0},
                       {"summary": {"errors": 0, "warnings": 0, "notices": 0}},
                       {"metadata": {**report["metadata"], "id": "other"}},
                       {"metadata": {**report["metadata"], "version": "old"}}):
            with self.assertRaisesRegex(ValueError, "lint status differs"):
                sign.verify_review(self.args.output, candidate, {**report, **change}, 1)
        for code in (0, 2, -1):
            with self.assertRaisesRegex(ValueError, "lint status differs"):
                sign.verify_review(self.args.output, candidate, report, code)
        for key in ("extension_id", "wallet_revision", "version", "unsigned_sha256", "tools"):
            review = json.loads(sign.REVIEW_FILE.read_text())
            sign.REVIEW_FILE.write_text(json.dumps({**review, key: "different"}))
            with self.assertRaisesRegex(ValueError, "candidate or validation tools differ"):
                sign.verify_review(self.args.output, candidate, report, 1)
            sign.REVIEW_FILE.write_text(json.dumps(review))
        changed_bundle = {**candidate, report["warnings"][0]["file"]: b"changed"}
        with self.assertRaisesRegex(ValueError, "Reviewed bundle changed"):
            sign.verify_review(self.args.output, changed_bundle, report, 1)

    def test_submission_version_must_upgrade_the_installed_wallet(self):
        self.args.version = "1.0.0"
        with self.assertRaisesRegex(ValueError, "newer than the installed"):
            prepare.prepare(self.args, self.repo)

    def test_dirty_source_and_changed_pinned_archive_stop_preparation(self):
        (self.wallet / "source.js").write_text("changed")
        with self.assertRaisesRegex(ValueError, "uncommitted"):
            prepare.prepare(self.args, self.repo)
        (self.wallet / "source.js").write_text("// human-readable wallet source\n")
        self.archive.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            prepare.prepare(self.args, self.repo)
        self.assertFalse(self.args.output.exists())

    def test_stale_launcher_or_local_wallet_override_is_rejected(self):
        original = self.browser.read_text()
        for old, new in [(self.revision[:12], "0" * 12),
                         (prepare.source_fingerprint(self.entries), "0" * 64),
                         (prepare.sha256(self.archive.read_bytes()), "0" * 64)]:
            self.args.output = self.root / f"rejected-{len(list(self.root.iterdir()))}"
            self.browser.write_text(original.replace(old, new))
            with self.assertRaises(ValueError):
                prepare.prepare(self.args, self.repo)

    def test_signing_refuses_tampering_and_requires_publisher_credentials(self):
        prepare.prepare(self.args, self.repo)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "WEB_EXT_API_KEY"):
                sign.sign(self.args.output, self.root / "signed")
        self.assertFalse((self.root / "signed").exists())
        (self.args.output / "extension/background.js").write_text("changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            sign.checked_preparation(self.args.output)
        (self.args.output / "unsigned.xpi").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            sign.checked_preparation(self.args.output)

    def test_submission_returns_an_unverified_receipt_without_exposing_credentials(self):
        prepare.prepare(self.args, self.repo)
        tools = self.root / "tools"
        for name, version in sign.TOOL_VERSIONS.items():
            package = tools / "node_modules" / name / "package.json"
            package.parent.mkdir(parents=True)
            package.write_text(json.dumps({"version": version}))
        output = self.root / "returned"
        expected = sign.checked_preparation(self.args.output)

        def service(command, check, **kwargs):
            if "lint" in command:
                self.assertIn("--warnings-as-errors", command)
                return SimpleNamespace(stdout=json.dumps({"summary": {"errors": 0, "warnings": 0}}), returncode=0)
            self.assertTrue(check)
            self.assertIn("--channel=unlisted", command)
            self.assertNotIn("fixture-issuer", command)
            self.assertNotIn("fixture-secret", command)
            source = prepare.read_archive(Path(command[command.index("--upload-source-code") + 1]))
            notes = json.loads(Path(command[command.index("--amo-metadata") + 1]).read_text())["version"]["approval_notes"]
            self.assertIn(source["REVIEWER.txt"].decode(), notes)
            self.assertIn("Chainapsis", notes)
            self.assertIn("DATA-DISCLOSURE.md", notes)
            self.assertIn("review-site.html", notes)
            self.assertEqual(json.loads(source["mozilla-lint.json"])["summary"]["warnings"], 0)
            self.assertNotIn("reviewed-findings.json", source)
            self.assertNotIn("reviewed-findings.json", notes)
            prepare.write_archive(output / "wallet.xpi", expected)

        with patch.object(sign, "ROOT", tools), patch.object(sign.subprocess, "run", service), \
                patch.dict(os.environ, {"WEB_EXT_API_KEY": "fixture-issuer", "WEB_EXT_API_SECRET": "fixture-secret"}):
            receipt = sign.sign(self.args.output, output)
        self.assertFalse(receipt["firefox_signature_verified"])
        self.assertEqual(receipt["sha256"], prepare.sha256((output / "wallet.xpi").read_bytes()))

    def test_rejects_a_different_linter_resolved_by_web_ext(self):
        for name, version in sign.TOOL_VERSIONS.items():
            directory = self.root / "node_modules" / name
            directory.mkdir(parents=True)
            (directory / "package.json").write_text(json.dumps({"version": version}))
        nested = self.root / "node_modules/web-ext/node_modules/addons-linter"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text('{"version":"1.0.0"}')
        with patch.object(sign, "ROOT", self.root), self.assertRaisesRegex(ValueError, "pinned signing tools"):
            sign.pinned_cli()

    def test_returned_payload_must_match_but_signature_filenames_are_not_trusted(self):
        candidate = self.root / "returned.xpi"
        prepare.write_archive(candidate, {**self.entries, "META-INF/cose.sig": b"not a real signature"})
        sign.verify_returned_content(candidate, self.entries)
        candidate.unlink()
        prepare.write_archive(candidate, {**self.entries, "background.js": b"changed"})
        with self.assertRaisesRegex(ValueError, "different"):
            sign.verify_returned_content(candidate, self.entries)

    def test_versions_and_unsafe_archive_paths_are_rejected(self):
        for version in ["", "1.2.3.4.5", "01.1", "1.65536", "1/2", "1-beta"]:
            with self.assertRaises(ValueError):
                prepare.release_version(version)
        for name in ["../outside", "/absolute", "C:/outside", "a\\outside", "./manifest.json"]:
            archive = self.root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr(name, b"bad")
            with self.assertRaises(ValueError):
                prepare.read_archive(archive)


if __name__ == "__main__":
    unittest.main()
