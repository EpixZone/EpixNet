#!/usr/bin/env python3
"""Inspect a built iOS .app for external native links and essential resources (macOS).

This is not App Store validation or a substitute for the archive privacy report.
"""
import argparse
import importlib.util
import pathlib
import plistlib
import subprocess
import sys

MACHO = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=pathlib.Path)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    errors = []
    with (args.app / "Info.plist").open("rb") as file:
        info = plistlib.load(file)
    for key in ("CFBundleShortVersionString", "CFBundleVersion", "NSCameraUsageDescription", "NSLocalNetworkUsageDescription"):
        if not info.get(key) or "$(" in str(info[key]):
            errors.append(f"missing/unexpanded {key}")
    with (args.app / "PrivacyInfo.xcprivacy").open("rb") as file:
        privacy = plistlib.load(file)
    categories = {item["NSPrivacyAccessedAPIType"] for item in privacy.get("NSPrivacyAccessedAPITypes", [])}
    for category in ("UserDefaults", "FileTimestamp", "SystemBootTime", "DiskSpace"):
        if "NSPrivacyAccessedAPICategory" + category not in categories:
            errors.append(f"missing required-reason category: {category}")
    count = 0
    for path in args.app.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as file:
            if file.read(4) not in MACHO:
                continue
        count += 1
        output = subprocess.check_output(["otool", "-L", str(path)], text=True)
        for line in output.splitlines()[1:]:
            linked = line.strip().split(" (", 1)[0]
            if linked.startswith("/") and not linked.startswith(("/System/Library/", "/usr/lib/")):
                errors.append(f"{path.name} depends on an external library: {linked}")
            if "libepix_ffi.dylib" in linked:
                errors.append(f"{path.name} must statically link the Rust core")
    if not count:
        errors.append("no Mach-O executable found")
    spec = importlib.util.spec_from_file_location("wallet_check", pathlib.Path(__file__).with_name("check-mobile-wallet.py"))
    wallet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wallet)
    errors.extend(wallet.check(args.app / "wallet-ext", args.release))
    for error in errors:
        print("FAIL:", error)
    if not errors:
        print(f"PASS: {count} native binaries have no external non-system links; required resources present")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
