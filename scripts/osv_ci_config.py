#!/usr/bin/env python3
"""Temporarily correct one stale OSV range for the verified Cargo.lock inventory."""

from datetime import datetime, timezone
from pathlib import Path
import tomllib


ADVISORY = "GHSA-qwgh-2vcv-g2f7"
EXPIRY = datetime(2026, 11, 3, tzinfo=timezone.utc)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CHECKSUMS = {
    "0.9.0": "4152116fd6e9dadb291ae18fc1ec3575ed6d84c29642d97890f4b4a3417297e4",
    "0.10.4": "3078c7629b62d3f0439517fa394996acacc5cbc91c5a20d8c658e77abd503a71",
    "0.12.1": "d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa",
}


def verified_inventory(packages):
    """Require every equivalent crate name to be an exact reviewed release."""
    versions = set()
    for package in packages:
        name = package["name"]
        # OSV treats underscores, hyphens and case as equivalent for crates.io.
        if name.lower().replace("_", "-") != "block-buffer":
            continue
        version = package.get("version")
        if (
            name != "block-buffer"
            or version not in CHECKSUMS
            or version in versions
            or package.get("source") != REGISTRY
            or package.get("checksum") != CHECKSUMS[version]
        ):
            return False
        versions.add(version)
    return bool(versions.intersection({"0.9.0", "0.10.4"}))


def build_config(base_config: str, lockfile: str, now: datetime) -> str:
    """Keep the normal policy unless this exact, unexpired exception applies."""
    policy = tomllib.loads(base_config)
    if any(entry["id"] == ADVISORY for entry in policy.get("IgnoredVulns", [])):
        raise ValueError(f"{ADVISORY} must not be ignored in the base policy")

    lock = tomllib.loads(lockfile)
    packages = lock.get("package")
    if lock.get("version") not in (3, 4) or not isinstance(packages, list) or not packages:
        raise ValueError("Expected a nonempty Cargo.lock version 3 or 4")
    if any(not isinstance(p, dict) or not isinstance(p.get("name"), str) for p in packages):
        raise ValueError("Invalid Cargo.lock package inventory")

    if now >= EXPIRY or not verified_inventory(packages):
        return base_config

    # The maintainer corrected the affected range to >=0.11.0,<0.12.1 on
    # 2026-10-27. OSV still reports <0.12.1. The old releases store the cursor
    # separately and predate ReadBuffer. Only this reviewed registry inventory
    # may use the exception, and the scanner independently enforces its expiry.
    # Remove this helper once OSV imports the corrected range:
    # https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7
    return base_config + '\n\n[[IgnoredVulns]]\n' + (
        f'id = "{ADVISORY}"\n'
        'ignoreUntil = 2026-11-03T00:00:00Z\n'
        'reason = "Temporary OSV range correction: exact registry releases '
        '0.9.0/0.10.4 are outside the maintainer affected range >=0.11.0,<0.12.1; '
        '0.12.1 is patched. Inventory and checksums verified by scripts/osv_ci_config.py. '
        'https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7"\n'
    )


def main():
    # This config is valid only for this one lockfile. Do not reuse it for a
    # directory, SBOM or another lockfile without checking that inventory too.
    base = Path("osv-scanner.toml").read_text(encoding="utf-8")
    lock = Path("Cargo.lock").read_text(encoding="utf-8")
    config = build_config(base, lock, datetime.now(timezone.utc))
    Path(".osv-scanner-ci.toml").write_text(config, encoding="utf-8")
    if config == base:
        print("Using the unchanged OSV policy; no temporary range correction applies.")
    else:
        print(f"Applied verified {ADVISORY} range correction until {EXPIRY.isoformat()}.")


if __name__ == "__main__":
    main()
