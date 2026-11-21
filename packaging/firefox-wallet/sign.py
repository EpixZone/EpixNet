#!/usr/bin/env python3
"""Submit a prepared wallet to Mozilla, without changing the installed wallet."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from prepare import read_archive, sha256

ROOT = Path(__file__).resolve().parent


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


def sign(prepared, output):
    for name in ("WEB_EXT_API_KEY", "WEB_EXT_API_SECRET"):
        if not os.environ.get(name):
            raise ValueError(f"Configure publisher-owned {name} in the signing environment")
    expected = checked_preparation(prepared)
    cli = ROOT / "node_modules/web-ext/bin/web-ext.js"
    package = json.loads((ROOT / "node_modules/web-ext/package.json").read_text())
    if package.get("version") != "10.8.0":
        raise ValueError("Install the pinned signing tools with npm ci --ignore-scripts")
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["node", str(cli), "sign", "--channel=unlisted",
                    "--source-dir", str(prepared / "extension"),
                    "--upload-source-code", str(prepared / "source.zip"),
                    "--artifacts-dir", str(output)], check=True)
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(sign(args.prepared.resolve(), args.output.resolve()), indent=2))


if __name__ == "__main__":
    main()
