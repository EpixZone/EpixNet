#!/usr/bin/env python3
"""Check EVX product dependency boundaries without building or linking targets."""

import argparse
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MOBILE = "tor,i2p-embedded,bridges,mesh,local-discovery"
RUNTIME = {"epix-evx", "evx-host", "evx-supervisor", "evx-workspace", "wasmtime"}
# Resolve each product separately so workspace feature unification cannot
# hide an unsupported platform or make a download-only embedder look enabled.
PROFILES = {
    "macos-browser": ("epix-browser", "aarch64-apple-darwin", None, True),
    "linux-browser": ("epix-browser", "x86_64-unknown-linux-gnu", None, True),
    "windows-browser": ("epix-browser", "x86_64-pc-windows-msvc", None, False),
    "macos-server": ("epix-server", "aarch64-apple-darwin", None, True),
    "linux-server": ("epix-server", "x86_64-unknown-linux-gnu", None, True),
    "windows-server": ("epix-server", "x86_64-pc-windows-msvc", None, False),
    "ios-ffi": ("epix-ffi", "aarch64-apple-ios", MOBILE, False),
    "android-ffi": ("epix-ffi", "aarch64-linux-android", MOBILE + ",bittorrent", False),
    "macos-nmh": ("epix-nmh", "aarch64-apple-darwin", None, False),
    "linux-nmh": ("epix-nmh", "x86_64-unknown-linux-gnu", None, False),
    "windows-nmh": ("epix-nmh", "x86_64-pc-windows-msvc", None, False),
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
    included = RUNTIME & packages
    if required and included != RUNTIME:
        raise SystemExit(f"{profile}: required EVX dependencies missing: {', '.join(sorted(RUNTIME - included))}")
    if not required and included:
        raise SystemExit(f"{profile}: unsupported EVX dependencies included: {', '.join(sorted(included))}")
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
