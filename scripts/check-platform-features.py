#!/usr/bin/env python3
"""Check store build profiles without unifying their Cargo features together."""

import argparse
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
# Inspect the real mobile target graphs, including bridges. Cargo tree does
# not link IPtProxy or need the Apple SDK / Android NDK.
MOBILE_FEATURES = "tor,i2p-embedded,bridges,mesh,local-discovery"
PROFILES = {
    "ios": ("epix-ffi", MOBILE_FEATURES, False, "aarch64-apple-ios"),
    "android": ("epix-ffi", MOBILE_FEATURES + ",bittorrent", True, "aarch64-linux-android"),
    "desktop": ("epix-browser", None, True, None),
}
BT_CONSUMERS = ("epix-node", "epix-runtime", "epix-ui", "epix-xite", "epix-discovery")


def check_profile(profile):
    package, features, enabled, target = PROFILES[profile]
    command = [
        "cargo", "tree", "--locked", "-p", package,
        "--edges", "normal,build", "--prefix", "none",
        "--format", "{p} features=[{f}]",
    ]
    if features is not None:
        command += ["--no-default-features", "--features", features]
    if target is not None:
        command += ["--target", target]
    # check=True is intentional: a failed Cargo command must fail the guard,
    # not masquerade as an empty, BitTorrent-free dependency tree.
    try:
        result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"{profile}: Cargo dependency resolution failed:\n{error.stderr}") from error
    packages = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"(\S+) v\S+ .*features=\[([^]]*)\](?: \(\*\))?", line)
        if match:
            packages.setdefault(match[1], set()).update(filter(None, match[2].split(",")))
    errors = []
    for consumer in BT_CONSUMERS:
        if consumer not in packages:
            errors.append(f"{consumer} missing from dependency tree")
        elif ("bittorrent" in packages[consumer]) != enabled:
            errors.append(f"{consumer}/bittorrent must be {'enabled' if enabled else 'absent'}")
    if ("epix-bt" in packages) != enabled:
        errors.append(f"epix-bt must be {'included' if enabled else 'absent'}")
    if errors:
        raise SystemExit(f"{profile}: " + "; ".join(errors))
    print(f"{profile}: BitTorrent engine and tracker discovery {'included' if enabled else 'excluded'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", nargs="*", help="Profiles to check: ios, android, desktop (default: all)")
    args = parser.parse_args()
    for profile in args.profiles or PROFILES:
        if profile not in PROFILES:
            parser.error(f"unknown profile: {profile}")
        check_profile(profile)


if __name__ == "__main__":
    main()
