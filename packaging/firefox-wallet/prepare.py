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


def write_archive(path, entries):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(entries.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, content)


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


def source_bundle(output, repositories, version, environment, raw_entries, final_entries):
    entries = {}
    snapshots = {}
    with tempfile.TemporaryDirectory(prefix="wallet-source-") as temporary:
        for name, repository in repositories.items():
            archive = Path(temporary) / f"{name}.zip"
            subprocess.run(["git", "-C", str(repository), "archive", "--format=zip", "HEAD", "-o", str(archive)], check=True)
            files = read_archive(archive)
            snapshots[name] = source_snapshot(repository, files)
            entries.update({f"{name}/{key}": value for key, value in files.items()})
    metadata = {"repositories": snapshots, "version": version, "environment": environment,
                "wallet_files": {name: sha256(content) for name, content in raw_entries.items()},
                "final_files": {name: sha256(content) for name, content in final_entries.items()}}
    entries["SOURCE.json"] = (json.dumps(metadata, indent=2) + "\n").encode()
    entries["rebuild.py"] = (ROOT / "packaging/firefox-wallet/rebuild.py").read_bytes()
    entries["wallet-build-env.sh"] = ("unset KEPLR_EXT_AMPLITUDE_API_KEY KEPLR_EXT_ANALYTICS_API_URL "
        "KEPLR_EXT_ANALYTICS_API_AUTH_TOKEN KEPLR_EXT_GOOGLE_MEASUREMENT_ID KEPLR_EXT_GOOGLE_API_KEY_FOR_MEASUREMENT\n"
        + "".join(f"export {key}={shlex.quote(value)}\n" for key, value in environment.items())).encode()
    entries["BUILD.txt"] = (
        f"Submitted release version: {version}\n"
        "Use Linux, Node 22, the included Yarn 3.4.1, Python 3, Git, protoc, Rust and EpixNet desktop build dependencies.\n"
        "From this extracted bundle, restore exact detached Git metadata (no synthetic commits):\n"
        "  python3 rebuild.py restore\n"
        "  . ./wallet-build-env.sh\n"
        "The policy URLs come from the checksum-verified original build metadata. Analytics credentials are unset. "
        "EPIX_MOBILE_STORE_BUILD=1 enables the upstream policy/analytics validation; it does not change emitted code.\n"
        "  cd epix-wallet\n"
        "  corepack enable\n"
        "  yarn install --immutable\n"
        "  yarn build:libs\n"
        "  yarn workspace @keplr-wallet/extension build\n"
        "  cd ..\n"
        "  python3 rebuild.py verify-wallet epix-wallet/apps/extension/build/firefox\n"
        "This must match every file of the pinned upstream archive before continuing.\n"
        "  cd EpixNet\n"
        "  EPIX_WALLET_DIST=\"$PWD/../epix-wallet/apps/extension/build/firefox\" cargo build --locked -p epix-browser --no-default-features\n"
        "  target/debug/epix-browser --export-wallet ../rebuilt.xpi\n"
        "  cd ..\n"
        "  python3 rebuild.py verify-final rebuilt.xpi\n"
        "The final comparison normalizes only manifest.version to the submitted version. All other payload bytes must match.\n"
        "See EpixNet/packaging/firefox-wallet/README.md for signing and remaining publisher requirements.\n"
    ).encode()
    write_archive(output, entries)


def prepare(args, root=ROOT):
    version = release_version(args.version)
    revision = repository_revision(root)
    wallet_revision = repository_revision(args.wallet_source)
    pin = (root / "shells/wallet-ext.rev").read_text().strip()
    if wallet_revision[:12] != pin:
        raise ValueError("Wallet source does not match the pinned release revision")
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
    manifest["version"] = version
    entries["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
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
    source = args.output / "source.zip"
    source_bundle(source, {"EpixNet": root, "epix-wallet": args.wallet_source}, version, environment, raw_entries, entries)
    provenance = {"schema": 1, "extension_id": WALLET_ID, "version": version,
                  "runtime_version": runtime_version, "epixnet_revision": revision,
                  "wallet_revision": wallet_revision, "wallet_archive_sha256": expected,
                  "runtime_export_sha256": metadata["archive_sha256"],
                  "unsigned_sha256": sha256(unsigned.read_bytes()), "source_sha256": sha256(source.read_bytes())}
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
