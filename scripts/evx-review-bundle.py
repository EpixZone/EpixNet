#!/usr/bin/env python3
"""Plan, create or verify a bounded EVX source review bundle. No network or builds."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 2000
EXACT = {
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "deny.toml",
    "osv-scanner.toml", ".gitleaks.toml", ".gitignore",
    ".github/workflows/ci.yml", ".github/workflows/build.yml",
    ".github/workflows/release.yml", ".github/workflows/security.yml",
    ".github/workflows/evx-platforms.yml",
    ".github/workflows/evx-mobile-fixtures.yml", ".github/workflows/evx-windows-fixture.yml",
    "docs/wrapper-sandbox.md", "ui/media/all.js",
    "scripts/check-evx-platforms.py", "scripts/test-evx-pulley-runtime.py",
    "scripts/check-evx-fuzz-lock.py", "scripts/test-evx-fuzz-lock.py",
    "scripts/evx-review-bundle.py", "scripts/test-evx-review-bundle.py",
    "scripts/evx-platform-acceptance.py", "scripts/test-evx-platform-acceptance.py",
    "packaging/macos/build-app.sh", "packaging/macos/test-evx-package.py",
    "packaging/macos/verify-evx-package.py", "packaging/linux/README.md",
    "packaging/linux/build-linux.sh", "packaging/linux/package-linux.py",
    "packaging/linux/test-install.sh", "packaging/linux/test-evx-package.py",
    "packaging/linux/verify-evx-worker.py", "fuzz/Cargo.toml", "fuzz/Cargo.lock",
    "fuzz/.gitignore",
    "crates/evx-activation/src/tests/fixtures/python_signed.json",
    "fuzz/README.md", "fuzz/results/campaign-summary.json",
    "fuzz/results/corpus-manifest.json", "fuzz/results/dependency-audit.json",
    "fuzz/results/2026-10-03-prealignment/manifest.json",
    "fuzz/results/2026-10-03-aligned/manifest.json",
    "fuzz/results/2026-10-04-lifecycle/manifest.json",
}
XPC_SUFFIXES = {".c", ".h", ".m", ".swift", ".py", ".sh", ".md", ".plist", ".entitlements"}
MOBILE_SUFFIXES = {".java", ".swift", ".py", ".md", ".xml", ".xcconfig"}


def eligible(name):
    """An intentional review scope, not an export of arbitrary repository data."""
    p = PurePosixPath(name)
    if p.is_absolute() or str(p) != name or any(part in {"", ".", ".."} for part in p.parts):
        return False
    if name in EXACT:
        return True
    if any(part.startswith(".") for part in p.parts):
        return False
    parts = p.parts
    if len(parts) == 2 and parts[0] == "docs":
        return p.name.startswith("evx") and p.suffix == ".md"
    if len(parts) >= 3 and parts[0] == "crates":
        if len(parts) == 3 and p.name == "Cargo.toml":
            return True  # Workspace dependency graph, without unrelated source.
        if parts[1].startswith("evx-") or parts[1] in {"epix-evx", "epix-ui", "epix-node"}:
            return (parts[2] in {"src", "tests", "examples", "native"} and p.suffix in {".rs", ".c", ".h"}) or (len(parts) == 3 and p.name == "build.rs")
    if parts[:3] == ("packaging", "macos", "xpc"):
        return len(parts) == 4 and p.suffix in XPC_SUFFIXES
    if parts[:3] in {("packaging", "android", "evx-fixture"), ("packaging", "android", "evx-runtime"), ("packaging", "ios", "evx-fixture")}:
        source_location = len(parts) == 4 or parts[3] in {"src", "tests", "Host", "Helper", "Shared", "Tests"}
        return source_location and (p.suffix in MOBILE_SUFFIXES or (len(parts) == 4 and p.name == "sdk-provenance.json"))
    if parts[:2] == ("fuzz", "fuzz_targets"):
        return len(parts) == 3 and p.suffix == ".rs"
    if parts[:2] == ("ui", "tests"):
        return len(parts) == 3 and p.suffix == ".cjs"
    return False


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    return result.stdout


def names(raw):
    return {name.decode("utf-8") for name in raw.split(b"\0") if name}


def read_source(root, name):
    # This is an operator export tool. Stop concurrent edits before taking the
    # final review snapshot. Refuse symlinks, special files and oversized input.
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink refused: {name}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError(f"nonregular or oversized source: {name}")
        data = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    if len(data) > MAX_FILE or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError(f"source changed or exceeded limit: {name}")
    data.decode("utf-8")  # Binary inputs and fuzz corpora are separate evidence.
    return data, "100755" if before.st_mode & stat.S_IXUSR else "100644"


def snapshot(root, include_untracked=()):
    tracked = names(git(root, "ls-files", "--cached", "-z"))
    untracked = names(git(root, "ls-files", "--others", "--exclude-standard", "-z"))
    extra = set(include_untracked)
    for name in extra:
        if not eligible(name) or name not in untracked:
            raise ValueError(f"not an eligible untracked source file: {name}")
    baseline = {}
    for item in git(root, "ls-tree", "-r", "HEAD", "-z").split(b"\0"):
        if item:
            metadata, path = item.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            baseline[path.decode()] = (mode, kind, oid)
    # A staged deletion no longer appears in ls-files, but the overlay must
    # still remove the baseline file from the reviewer's checkout.
    selected = {name for name in tracked | baseline.keys() if eligible(name)} | extra
    if len(selected) > MAX_FILES:
        raise ValueError("review file count exceeds limit")
    records, blobs = [], {}
    total = 0
    for name in sorted(selected):
        base = baseline.get(name)
        record = {"path": name, "head_blob": base[2] if base else None}
        try:
            data, mode = read_source(root, name)
        except FileNotFoundError:
            if name in extra:
                raise ValueError(f"selected source disappeared: {name}") from None
            record["status"] = "deleted"
        else:
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError("review source size exceeds limit")
            oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            record.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(), mode=mode,
                          status="unchanged" if base == (mode, "blob", oid) else "modified" if base else "added")
            blobs[name] = data
        records.append(record)
    manifest = {
        "format": "evx-source-review-v1",
        "head": git(root, "rev-parse", "--verify", "HEAD").decode().strip(),
        "scope": "EVX source review overlay; requires the full repository at head to build",
        "evidence": "No tests are run or certified by this export",
        "files": records,
        "omitted_untracked_sources": sorted(name for name in untracked - selected if eligible(name)),
    }
    return manifest, blobs


def encode(manifest, blobs):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        entries = {"manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
        entries.update({"source/" + name: data for name, data in blobs.items()})
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buffer.getvalue()


def verify(path):
    # Never extract or execute supplied content. Bound both compressed input and
    # each decompressed member before verifying the manifest's exact inventory.
    if path.stat().st_size > MAX_TOTAL + 2 * MAX_FILE:
        raise ValueError("archive exceeds size limit")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES + 1 or len({e.filename for e in entries}) != len(entries):
            raise ValueError("duplicate or excessive archive entries")
        if any(e.file_size > MAX_FILE for e in entries) or sum(e.file_size for e in entries) > MAX_TOTAL + MAX_FILE:
            raise ValueError("uncompressed archive exceeds limit")
        manifest = json.loads(archive.read("manifest.json"))
        if not isinstance(manifest, dict) or manifest.get("format") != "evx-source-review-v1":
            raise ValueError("unknown review format")
        if not isinstance(manifest.get("files"), list) or len(manifest["files"]) > MAX_FILES:
            raise ValueError("invalid manifest inventory")
        expected = {"manifest.json"}
        seen = set()
        for record in manifest["files"]:
            name = record["path"]
            if not eligible(name) or name in seen:
                raise ValueError("invalid or duplicate source path")
            seen.add(name)
            if record["status"] == "deleted":
                continue
            if record["status"] not in {"added", "modified", "unchanged"} or record["mode"] not in {"100644", "100755"}:
                raise ValueError("invalid source metadata")
            entry = "source/" + name
            data = archive.read(entry)
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError(f"source hash mismatch: {name}")
            data.decode("utf-8")
            expected.add(entry)
        if expected != {e.filename for e in entries}:
            raise ValueError("archive inventory does not match manifest")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Create a new ZIP outside this repository; never overwrite")
    parser.add_argument("--include-untracked", action="append", default=[], metavar="PATH", help="Explicit eligible repository-relative source path; repeat as needed")
    parser.add_argument("--verify", type=Path, help="Verify an existing bundle without extracting or executing it")
    args = parser.parse_args()
    try:
        if args.verify:
            if args.output or args.include_untracked:
                parser.error("--verify cannot be combined with export options")
            manifest = verify(args.verify)
            print(json.dumps({"verified_files": len(manifest["files"]), "head": manifest["head"]}, sort_keys=True))
            return
        manifest, blobs = snapshot(ROOT, args.include_untracked)
        if args.output:
            target = args.output.absolute()
            if target.resolve().is_relative_to(ROOT.resolve()):
                parser.error("output must be outside the repository")
            data = encode(manifest, blobs)
            with target.open("xb") as stream:
                stream.write(data)
            print(json.dumps({"files": len(manifest["files"]), "sha256": hashlib.sha256(data).hexdigest(), "omitted_untracked_sources": manifest["omitted_untracked_sources"]}, sort_keys=True))
        else:
            print(json.dumps(manifest, sort_keys=True, indent=2))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"review bundle refused: {error}\n")


if __name__ == "__main__":
    main()
