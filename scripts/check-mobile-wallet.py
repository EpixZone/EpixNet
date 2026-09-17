#!/usr/bin/env python3
"""Check an explicitly staged mobile wallet. --release also enforces provenance/policies.

This validates packaging, not the truth of policy-page disclosures or store eligibility.
"""
import argparse
import json
import pathlib
import re
import sys
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]


def check(directory, release=False):
    errors = []
    for name in ("manifest.json", "mobile.html", "mobile-register.html", "mobileProvider.bundle.js"):
        if not (directory / name).is_file() or (directory / name).stat().st_size == 0:
            errors.append(f"missing wallet asset: {name}")
    try:
        info = json.loads((directory / "epix-mobile-build.json").read_text())
    except (OSError, ValueError):
        return errors + ["missing/invalid epix-mobile-build.json; rebuild the wallet source"]
    if info.get("schema") != 1 or info.get("providerProtocol") != 1:
        errors.append("unsupported mobile provider metadata")
    if release:
        if info.get("analyticsConfigured") is not False:
            errors.append("mobile privacy policy requires analyticsConfigured=false; rebuild without analytics credentials")
        revision = info.get("revision", "")
        pin = (ROOT / "shells/wallet-ext.rev").read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{12,40}", pin) or not re.fullmatch(r"[0-9a-f]{40}", revision) or not revision.startswith(pin):
            errors.append("wallet source revision does not match shells/wallet-ext.rev")
        if info.get("modifiedSource") is not False:
            errors.append("wallet was built from modified/uncommitted source")
        for name in ("termsURL", "privacyURL"):
            url = urlsplit(info.get(name, ""))
            host = url.hostname or ""
            if (url.scheme != "https" or not host or url.username or url.password
                    or host in ("localhost", "127.0.0.1", "::1", "example.com", "discord.gg", "discord.com")
                    or host.endswith((".example", ".invalid", ".localhost"))):
                errors.append(f"{name} must be the operator's published HTTPS policy page")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    errors = check(args.directory, args.release)
    for error in errors:
        print("FAIL:", error)
    if not errors:
        print("PASS: mobile wallet assets" + (", pinned source and policy configuration" if args.release else " (development check)"))
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
