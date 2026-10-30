#!/usr/bin/env python3
"""Check EVX product dependency boundaries without building or linking targets."""

import argparse
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MOBILE = "tor,i2p-embedded,bridges,mesh,local-discovery"
# The EVX runtime a supported product must carry, per platform. The Windows
# backend adds the Win32 primitives crate; an excluded product must carry
# nothing from either set.
UNIX_RUNTIME = {"epix-evx", "evx-host", "evx-supervisor", "evx-workspace", "wasmtime"}
WINDOWS_RUNTIME = UNIX_RUNTIME | {"evx-windows-native"}
ANY_RUNTIME = UNIX_RUNTIME | WINDOWS_RUNTIME
# Resolve each product separately so workspace feature unification cannot
# hide an unsupported platform or make a download-only embedder look enabled.
# Each profile: package, target, feature override, required runtime set
# (None when the product must exclude EVX).
PROFILES = {
    "macos-browser": ("epix-browser", "aarch64-apple-darwin", None, UNIX_RUNTIME),
    "linux-browser": ("epix-browser", "x86_64-unknown-linux-gnu", None, UNIX_RUNTIME),
    "windows-browser": ("epix-browser", "x86_64-pc-windows-msvc", None, WINDOWS_RUNTIME),
    "macos-server": ("epix-server", "aarch64-apple-darwin", None, UNIX_RUNTIME),
    "linux-server": ("epix-server", "x86_64-unknown-linux-gnu", None, UNIX_RUNTIME),
    "windows-server": ("epix-server", "x86_64-pc-windows-msvc", None, WINDOWS_RUNTIME),
    "ios-ffi": ("epix-ffi", "aarch64-apple-ios", MOBILE, None),
    "android-ffi": ("epix-ffi", "aarch64-linux-android", MOBILE + ",bittorrent", None),
    "macos-nmh": ("epix-nmh", "aarch64-apple-darwin", None, None),
    "linux-nmh": ("epix-nmh", "x86_64-unknown-linux-gnu", None, None),
    "windows-nmh": ("epix-nmh", "x86_64-pc-windows-msvc", None, None),
}


def check(profile):
    package, target, features, required = PROFILES[profile]
    command = ["cargo", "tree", "--locked", "-p", package, "--target", target,
               "--edges", "normal,build", "--prefix", "none", "--format", "{p}"]
    if features is not None:
        command += ["--no-default-features", "--features", features]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f"{profile}: Cargo dependency resolution failed:\n{result.stderr}")
    packages = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    if package not in packages:
        raise SystemExit(f"{profile}: product missing from Cargo dependency output")
    included = ANY_RUNTIME & packages
    if required is None and included:
        raise SystemExit(f"{profile}: unsupported EVX dependencies included: {', '.join(sorted(included))}")
    if required is not None and included != required:
        missing = sorted(required - included)
        extra = sorted(included - required)
        raise SystemExit(f"{profile}: EVX dependency set mismatch; missing: {', '.join(missing) or 'none'}; unexpected: {', '.join(extra) or 'none'}")
    print(f"{profile}: EVX runtime {'included' if required else 'excluded'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", nargs="*", help="Named product profiles; default: all")
    args = parser.parse_args()
    for profile in args.profiles or PROFILES:
        if profile not in PROFILES:
            parser.error(f"unknown profile: {profile}")
        check(profile)


if __name__ == "__main__":
    main()
