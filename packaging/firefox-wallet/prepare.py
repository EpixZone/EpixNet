#!/usr/bin/env python3
"""Prepare final wallet bytes and matching source for Mozilla self-distribution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import shlex
import subprocess
import tempfile
import zipfile

from rebuild import reviewed_gecko_settings, submission_manifest, write_archive

ROOT = Path(__file__).resolve().parents[2]
WALLET_ID = "wallet@epix.zone"
MAX_CONTENT = 512 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_archive(path):
    entries = {}
    with zipfile.ZipFile(path) as archive:
        total = 0
        for info in archive.infolist():
            name = info.filename
            relative = PurePosixPath(name)
            if (relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name
                    or str(relative) != name.rstrip("/") or any(ord(char) < 32 for char in name) or not name):
                raise ValueError("Archive contains an unsafe path")
            if info.is_dir():
                continue
            if name in entries or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("Archive contains duplicate files or symbolic links")
            total += info.file_size
            if total > MAX_CONTENT:
                raise ValueError("Archive exceeds the content limit")
            entries[name] = archive.read(info)
    return entries


def source_fingerprint(entries):
    digest = hashlib.sha256()
    for name, content in sorted(entries.items()):
        if name == "README.md":
            continue
        encoded = name.encode("utf-8")
        digest.update(struct.pack("<Q", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack("<Q", len(content)))
        digest.update(content)
    return digest.hexdigest()


def repository_revision(path):
    revision = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Source must be a committed Git checkout")
    if subprocess.run(["git", "-C", str(path), "diff", "--quiet", "HEAD", "--"], check=False).returncode:
        raise ValueError("Source has uncommitted tracked changes; commit and rebuild first")
    return revision


def release_version(value):
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){0,3}", value):
        raise ValueError("Version must contain one to four numeric components")
    if any(int(part) > 65535 for part in value.split(".")):
        raise ValueError("Version components must not exceed 65535")
    return value


def wallet_build_environment(entries, revision):
    metadata = json.loads(entries["epix-mobile-build.json"])
    if (metadata.get("revision") != revision or metadata.get("modifiedSource") is not False
            or metadata.get("analyticsConfigured") is not False):
        raise ValueError("Pinned wallet build metadata is not a clean, analytics-free source build")
    environment = {"EPIX_MOBILE_STORE_BUILD": "1"}
    for key, field in (("EPIX_TERMS_URL", "termsURL"), ("EPIX_PRIVACY_URL", "privacyURL")):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.startswith("https://"):
            raise ValueError("Pinned wallet build metadata lacks a public HTTPS policy URL")
        environment[key] = value
    return environment


def source_snapshot(repository, entries):
    revision = repository_revision(repository)
    tree = subprocess.check_output(["git", "-C", str(repository), "ls-tree", "-rz", "HEAD"])
    files = []
    for item in tree.rstrip(b"\0").split(b"\0"):
        header, name = item.split(b"\t", 1)
        mode, kind, blob = header.decode().split()
        name = name.decode()
        if kind != "blob" or mode not in ("100644", "100755") or name not in entries:
            raise ValueError("Source snapshot contains unsupported or omitted Git entries")
        content = entries[name]
        # Git blob identity, not a security digest. SHA-256 protects the bundle.
        identity = hashlib.sha1(f"blob {len(content)}\0".encode() + content, usedforsecurity=False).hexdigest()
        if identity != blob:
            raise ValueError("Archived source differs from its committed Git content")
        files.append({"path": name, "mode": mode, "blob": blob})
    commit = subprocess.check_output(["git", "-C", str(repository), "cat-file", "commit", revision]).decode()
    return {"revision": revision, "commit": commit, "files": files}


def source_bundle(output, repositories, version, environment, raw_entries, final_entries, unsigned_sha256):
    entries = {}
    snapshots = {}
    with tempfile.TemporaryDirectory(prefix="wallet-source-") as temporary:
        for name, repository in repositories.items():
            archive = Path(temporary) / f"{name}.zip"
            subprocess.run(["git", "-C", str(repository), "archive", "--format=zip", "HEAD", "-o", str(archive)], check=True)
            files = read_archive(archive)
            snapshots[name] = source_snapshot(repository, files)
            entries.update({f"{name}/{key}": value for key, value in files.items()})
    wallet_revision = snapshots["epix-wallet"]["revision"]
    epixnet_revision = snapshots["EpixNet"]["revision"]
    disclosure = json.loads(entries["EpixNet/packaging/firefox-wallet/data-disclosure.json"])
    tools = disclosure["build_tools"]
    if json.loads(entries["epix-wallet/package.json"])["packageManager"] != "yarn@" + tools["yarn"]:
        raise ValueError("Reviewed Yarn version differs from the wallet source")
    review_directory = "EpixNet/packaging/firefox-wallet/"
    entries["REVIEWER.txt"] = (
        f"Epix Wallet {version} ({WALLET_ID}) for unlisted distribution with EpixNet.\n"
        f"Wallet source: https://github.com/EpixZone/epix-wallet/tree/{wallet_revision}\n"
        f"EpixNet packaging: https://github.com/EpixZone/EpixNet/tree/{epixnet_revision}\n"
        f"Privacy policy: {environment['EPIX_PRIVACY_URL']}\nTerms: {environment['EPIX_TERMS_URL']}\n\n"
    ).encode() + entries[review_directory + "REVIEWER.txt"]
    metadata = {"repositories": snapshots, "version": version, "environment": environment,
                "unsigned_sha256": unsigned_sha256,
                "wallet_files": {name: sha256(content) for name, content in raw_entries.items()},
                "final_files": {name: sha256(content) for name, content in final_entries.items()}}
    entries["SOURCE.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    for name in ("build.sh", "rebuild.py", "review-tools.sha256"):
        entries[name] = (ROOT / "packaging/firefox-wallet" / name).read_bytes()
    build_environment = dict(environment, REVIEW_NODE=tools["node"], REVIEW_PROTOC=tools["protoc"], REVIEW_YARN=tools["yarn"])
    entries["wallet-build-env.sh"] = ("unset KEPLR_EXT_AMPLITUDE_API_KEY KEPLR_EXT_ANALYTICS_API_URL "
        "KEPLR_EXT_ANALYTICS_API_AUTH_TOKEN KEPLR_EXT_GOOGLE_MEASUREMENT_ID KEPLR_EXT_GOOGLE_API_KEY_FOR_MEASUREMENT\n"
        + "".join(f"export {key}={shlex.quote(value)}\n" for key, value in build_environment.items())).encode()
    entries["BUILD.txt"] = (
        f"Rebuild Epix Wallet {version} on Ubuntu 24.04 LTS (ARM64 or x86_64).\n"
        f"Wallet release build: https://github.com/EpixZone/epix-wallet/actions/runs/{tools['release_run']}\n"
        f"The script installs Node {tools['node']}, the included Yarn {tools['yarn']} and protoc {tools['protoc']}. "
        "It uses the complete compiler distribution with its standard Protobuf headers and Rust 1.100.0.\n"
        "Use a fresh directory with 4 CPUs, 10 GB RAM and 35 GB free disk. Network access is needed for tools "
        "and locked dependencies. On a fresh Ubuntu system install these packages first:\n"
        "  sudo apt-get update\n"
        "  sudo apt-get install -y ca-certificates curl xz-utils unzip python3 git build-essential cmake "
        "pkg-config libudev-dev libgtk-3-dev libayatana-appindicator3-dev libxdo-dev\n"
        "Extract this source ZIP, then run the following from the directory containing BUILD.txt:\n"
        "  bash build.sh\n"
        "The script restores both exact Git revisions and builds the Firefox wallet from the submitted sources. "
        "It verifies every upstream file, exports the rebuilt wallet through the EpixNet launcher, "
        "and applies the submission manifest and deterministic ZIP settings. "
        "The result is rebuilt.xpi in this directory. Compare the unsigned archive bytes with:\n"
        f"  echo '{unsigned_sha256}  rebuilt.xpi' | sha256sum -c -\n"
        "For the optional tests in REVIEWER.txt, make the same Node and Yarn available in your shell:\n"
        '  export PATH="$PWD/.review-build/node/bin:$PATH"\n'
    ).encode()
    write_archive(output, entries)


def prepare(args, root=ROOT):
    version = release_version(args.version)
    revision = repository_revision(root)
    wallet_revision = repository_revision(args.wallet_source)
    pin = (root / "shells/wallet-ext.rev").read_text().strip()
    if wallet_revision[:12] != pin:
        raise ValueError("Wallet source does not match the pinned release revision")
    settings = reviewed_gecko_settings(root, wallet_revision)
    expected = (root / "shells/wallet-ext.sha256").read_text().split()[0]
    original = args.wallet_archive.read_bytes()
    if sha256(original) != expected:
        raise ValueError("Wallet archive does not match the pinned SHA-256")
    raw_entries = read_archive(args.wallet_archive)
    environment = wallet_build_environment(raw_entries, wallet_revision)
    args.output.mkdir(parents=True, exist_ok=False)
    exported = args.output / "runtime-export.xpi"
    result = subprocess.run([str(args.browser), "--export-wallet", str(exported)], capture_output=True, text=True, check=True)
    metadata = json.loads(result.stdout)
    built_revision = metadata.get("source_revision", "")
    if not re.fullmatch(r"[0-9a-f]{7,40}", built_revision) or not revision.startswith(built_revision):
        raise ValueError("Launcher does not match this committed EpixNet source; rebuild it")
    if metadata.get("wallet_revision") != pin or metadata.get("wallet_source_sha256") != source_fingerprint(raw_entries):
        raise ValueError("Launcher embeds a different wallet build; rebuild without a local wallet override")
    if metadata.get("archive_sha256") != sha256(exported.read_bytes()):
        raise ValueError("Exported wallet digest does not match the launcher receipt")
    entries = read_archive(exported)
    if any(name.upper().startswith("META-INF/") for name in entries):
        raise ValueError("Signing input unexpectedly contains signature metadata")
    manifest = json.loads(entries["manifest.json"])
    identity = manifest.get("browser_specific_settings", manifest.get("applications", {}))
    if identity.get("gecko", {}).get("id") != WALLET_ID:
        raise ValueError("Signing input is not the Epix Wallet extension")
    runtime_version = manifest["version"]
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", runtime_version):
        raise ValueError("Cannot compare the installed wallet version for a safe in-place update")
    installed = tuple(int(part) for part in runtime_version.split("."))
    submitted = tuple(int(part) for part in version.split("."))
    if submitted + (0,) * (4 - len(submitted)) <= installed + (0,) * (4 - len(installed)):
        raise ValueError("Submitted version must be newer than the installed wallet version")
    entries["manifest.json"] = submission_manifest(manifest, version, settings)
    extension = args.output / "extension"
    extension.mkdir()
    for name, content in entries.items():
        target = extension / name
        if not target.resolve().is_relative_to(extension.resolve()):
            raise ValueError("Prepared extension path escapes its output directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    unsigned = args.output / "unsigned.xpi"
    write_archive(unsigned, entries)
    unsigned_sha256 = sha256(unsigned.read_bytes())
    source = args.output / "source.zip"
    source_bundle(source, {"EpixNet": root, "epix-wallet": args.wallet_source}, version, environment, raw_entries, entries, unsigned_sha256)
    provenance = {"schema": 1, "extension_id": WALLET_ID, "version": version,
                  "runtime_version": runtime_version, "epixnet_revision": revision,
                  "wallet_revision": wallet_revision, "wallet_archive_sha256": expected,
                  "runtime_export_sha256": metadata["archive_sha256"],
                  "unsigned_sha256": unsigned_sha256, "source_sha256": sha256(source.read_bytes())}
    (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--wallet-source", type=Path, required=True)
    parser.add_argument("--wallet-archive", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args), indent=2))


if __name__ == "__main__":
    main()
