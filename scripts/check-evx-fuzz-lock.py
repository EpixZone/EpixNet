#!/usr/bin/env python3
"""Require fuzzed workspace dependencies to use the shipping locked versions."""

from pathlib import Path
import sys
import tomllib


def mismatches(application, fuzz):
    shipping = {}
    for package in application["package"]:
        shipping.setdefault(package["name"], set()).add(
            (package["version"], package.get("source"), package.get("checksum"))
        )
    return sorted(
        f"{package['name']} {package['version']}"
        for package in fuzz["package"]
        if package["name"] in shipping
        and (package["version"], package.get("source"), package.get("checksum"))
        not in shipping[package["name"]]
    )


def main():
    root = Path(__file__).resolve().parents[1]
    with (root / "Cargo.lock").open("rb") as application:
        with (root / "fuzz/Cargo.lock").open("rb") as fuzz:
            differences = mismatches(tomllib.load(application), tomllib.load(fuzz))
    if differences:
        print("Fuzz dependencies differ from the shipping lock:", file=sys.stderr)
        print("\n".join(differences), file=sys.stderr)
        return 1
    print("Fuzz dependencies match shipping versions, sources and checksums.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
