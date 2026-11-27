#!/usr/bin/env python3
"""Submit a prepared wallet to Mozilla, without changing the installed wallet."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

from prepare import read_archive, sha256

ROOT = Path(__file__).resolve().parent
REVIEW_FILE = ROOT / "mozilla-review.json"
TOOL_VERSIONS = {"web-ext": "10.8.0", "addons-linter": "10.14.0"}
# Mozilla's Version.approval_notes model and API share this character limit.
AMO_NOTES_LIMIT = 3000


def checked_preparation(prepared):
    receipt = json.loads((prepared / "provenance.json").read_text())
    for name, field in (("unsigned.xpi", "unsigned_sha256"), ("source.zip", "source_sha256")):
        if sha256((prepared / name).read_bytes()) != receipt.get(field):
            raise ValueError(f"Prepared {name} changed after validation")
    expected = read_archive(prepared / "unsigned.xpi")
    extension = prepared / "extension"
    paths = list(extension.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("Prepared extension contains symbolic links")
    actual = {path.relative_to(extension).as_posix(): path.read_bytes() for path in paths if path.is_file()}
    if actual != expected:
        raise ValueError("Prepared extension files changed after validation")
    return expected


def verify_returned_content(candidate, expected):
    entries = read_archive(candidate)
    payload = {name: content for name, content in entries.items() if not name.upper().startswith("META-INF/")}
    if payload != expected:
        raise ValueError("Mozilla's returned artifact has different extension content")
    # File names alone are not cryptographic signature verification. Actual
    # Firefox signature validation is still required before runtime adoption.


def pinned_cli():
    modules = ROOT / "node_modules"
    for name, version in TOOL_VERSIONS.items():
        directory = modules / name
        nested = modules / "web-ext/node_modules" / name
        if name == "addons-linter" and nested.exists():
            directory = nested
        package = json.loads((directory / "package.json").read_text())
        if package.get("version") != version:
            raise ValueError("Install the pinned signing tools with npm ci --ignore-scripts")
    return modules / "web-ext/bin/web-ext.js"


def verify_review(prepared, entries, report, exit_code):
    review = json.loads(REVIEW_FILE.read_text())
    receipt = json.loads((prepared / "provenance.json").read_text())
    if (review["tools"] != TOOL_VERSIONS or
            any(receipt.get(key) != review[key] for key in ("extension_id", "wallet_revision", "version", "unsigned_sha256")) or
            json.loads(entries["epix-mobile-build.json"])["revision"] != review["wallet_revision"]):
        raise ValueError("The candidate or validation tools differ from the publisher review")
    findings = review["findings"]
    count = len(findings)
    metadata = report.get("metadata", {})
    if (exit_code != 1 or report.get("errors") != [] or report.get("notices") != [] or
            report.get("count") != count or metadata.get("id") != review["extension_id"] or
            metadata.get("version") != review["version"] or
            report.get("summary") != {"errors": 0, "notices": 0, "warnings": count}):
        raise ValueError("Mozilla lint status differs from the publisher review")
    # File processing order can vary between runs. Match every complete diagnostic,
    # including duplicates, and bind its reported location to the reviewed bytes.
    reviewed = [finding["diagnostic"] for finding in findings]
    if sorted(json.dumps(row, sort_keys=True) for row in report["warnings"]) != sorted(
            json.dumps(row, sort_keys=True) for row in reviewed):
        raise ValueError("Mozilla lint diagnostics differ from the publisher review")
    for finding in findings:
        name = finding["diagnostic"]["file"]
        if sha256(entries[name]) != finding["bundle_sha256"]:
            raise ValueError(f"Reviewed bundle changed: {name}")


def run_lint(prepared, entries, reviewed_warnings):
    result = subprocess.run(["node", str(pinned_cli()), "lint", "--warnings-as-errors", "--output=json",
                             "--source-dir", str(prepared / "extension")], capture_output=True, text=True, check=False)
    (prepared / "lint.json").write_text(result.stdout)
    report = json.loads(result.stdout)
    summary = report.get("summary", {})
    if reviewed_warnings:
        verify_review(prepared, entries, report, result.returncode)
    elif result.returncode or summary.get("errors", 1) or summary.get("warnings", 1):
        raise ValueError("Mozilla lint requires publisher/upstream review; see retained lint.json. Submission was not attempted.")
    return summary


def lint_preparation(prepared, reviewed_warnings=False):
    return run_lint(prepared, checked_preparation(prepared), reviewed_warnings)


def review_upload(prepared, output, reviewed_warnings):
    source = output / "review-source.zip"
    shutil.copyfile(prepared / "source.zip", source)
    files = {"mozilla-lint.json": prepared / "lint.json"}
    if reviewed_warnings:
        files["reviewed-findings.json"] = REVIEW_FILE
    with zipfile.ZipFile(source, "a") as archive:
        notes = archive.read("REVIEWER.txt").decode("utf-8")
        for name, path in files.items():
            if name in archive.namelist():
                raise ValueError(f"Source archive already contains {name}")
            archive.writestr(zipfile.ZipInfo(name), path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
    notes += "\nThe complete validator report is in mozilla-lint.json."
    if reviewed_warnings:
        notes += " reviewed-findings.json gives the source, location, bundle digest and review for each warning."
    if len(notes) > AMO_NOTES_LIMIT:
        raise ValueError("Reviewer notes exceed Mozilla's 3,000-character limit")
    metadata = output / "amo-metadata.json"
    metadata.write_text(json.dumps({"version": {"approval_notes": notes}}, indent=2) + "\n")
    return source, metadata


def prepare_upload(prepared, output, reviewed_warnings=False):
    expected = checked_preparation(prepared)
    run_lint(prepared, expected, reviewed_warnings)
    output.mkdir(parents=True, exist_ok=False)
    source, metadata = review_upload(prepared, output, reviewed_warnings)
    return expected, source, metadata


def sign(prepared, output, reviewed_warnings=False):
    for name in ("WEB_EXT_API_KEY", "WEB_EXT_API_SECRET"):
        if not os.environ.get(name):
            raise ValueError(f"Configure publisher-owned {name} in the signing environment")
    expected, source, metadata = prepare_upload(prepared, output, reviewed_warnings)
    subprocess.run(["node", str(pinned_cli()), "sign", "--channel=unlisted",
                    "--source-dir", str(prepared / "extension"),
                    "--upload-source-code", str(source),
                    "--artifacts-dir", str(output), "--amo-metadata", str(metadata)], check=True)
    candidates = list(output.glob("*.xpi"))
    if len(candidates) != 1:
        raise ValueError("Mozilla signing did not produce exactly one XPI")
    candidate = candidates[0]
    verify_returned_content(candidate, expected)
    result = {"artifact": candidate.name, "sha256": sha256(candidate.read_bytes()),
              "firefox_signature_verified": False,
              "next_step": "Verify with Firefox signature checks enabled before pinning and installing these exact bytes."}
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--lint-only", action="store_true")
    modes.add_argument("--prepare-only", action="store_true", help="Write the source archive and metadata for review")
    parser.add_argument("--reviewed-warnings", action=argparse.BooleanOptionalAction, default=False,
                        help="Require the exact publisher-reviewed candidate, tool versions and diagnostics")
    args = parser.parse_args()
    if args.lint_only:
        print(json.dumps(lint_preparation(args.prepared.resolve(), args.reviewed_warnings), indent=2))
    elif args.output is None:
        parser.error("preparing upload files or submitting requires --output")
    elif args.prepare_only:
        _, source, metadata = prepare_upload(args.prepared.resolve(), args.output.resolve(), args.reviewed_warnings)
        print(f"Prepared {source} and {metadata}")
    else:
        print(json.dumps(sign(args.prepared.resolve(), args.output.resolve(), args.reviewed_warnings), indent=2))


if __name__ == "__main__":
    main()
