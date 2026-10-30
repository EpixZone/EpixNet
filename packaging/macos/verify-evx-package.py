#!/usr/bin/env python3
"""Check EVX package properties, without claiming runtime or App Store acceptance."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import posixpath
import subprocess
import sys
from xml.parsers.expat import ExpatError


class PackageError(Exception):
    pass


MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
SIGNING_METADATA = {"application-identifier", "com.apple.application-identifier",
                    "com.apple.developer.team-identifier"}


def run_tool(command):
    try:
        result = subprocess.run(command, capture_output=True, timeout=30,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PackageError(f"{Path(command[0]).name} unavailable or timed out") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace")[:2000].strip()
        raise PackageError(f"{Path(command[0]).name} failed: {detail}")
    if len(result.stdout) > 1024 * 1024:
        raise PackageError(f"{Path(command[0]).name} output exceeded package inspection limit")
    return result.stdout


def worker_path(app):
    # Do not resolve symlinks: a linked worker or linked bundle component is
    # outside this package's intended signature and placement checks.
    app = Path(os.path.abspath(app))
    worker = app / "Contents" / "MacOS" / "evx-worker"
    for path in (app, app / "Contents", worker.parent, worker):
        if path.is_symlink():
            raise PackageError(f"symlink in EVX package path: {path}")
        if not path.exists():
            raise PackageError(f"missing EVX package path: {path}")
    if not worker.is_file() or not os.access(worker, os.X_OK):
        raise PackageError("EVX worker is not an executable regular file")
    with worker.open("rb") as source:
        if source.read(4) not in MACHO_MAGIC:
            raise PackageError("EVX worker is not a Mach-O binary")
    return app, worker


def check_entitlements(encoded):
    # codesign emits no plist for a signature without entitlements.
    if not encoded.strip():
        return
    try:
        entitlements = plistlib.loads(encoded)
    except (ValueError, plistlib.InvalidFileException, ExpatError) as error:
        raise PackageError("invalid worker entitlements") from error
    if not isinstance(entitlements, dict):
        raise PackageError("worker entitlements must be a dictionary")
    for key, value in entitlements.items():
        if key in SIGNING_METADATA and isinstance(value, str) and value:
            continue
        if key == "com.apple.security.get-task-allow" and value is False:
            continue
        # This is the existing direct-child profile, whose worker declares no
        # extra authority. A new entitlement requires an explicit profile and
        # corresponding runtime acceptance, not a packaging-only exception.
        raise PackageError(f"unexpected worker entitlement for direct-child profile: {key}")


def check_dependencies(encoded):
    try:
        lines = encoded.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PackageError("invalid dependency inspection output") from error
    count = 0
    for line in lines:
        if not line.strip() or line.endswith(":"):
            continue  # otool image and universal-architecture headings
        dependency, separator, _version = line.strip().partition(" (compatibility version ")
        if not separator:
            raise PackageError("unrecognized worker dependency inspection output")
        count += 1
        if posixpath.normpath(dependency) != dependency or not dependency.startswith(
            ("/usr/lib/", "/System/Library/")
        ):
            raise PackageError(f"worker dependency is not a fixed system library: {dependency}")
    if count == 0:
        raise PackageError("worker dependency inspection returned no libraries")


def verify(app, *, profile, run_tool=run_tool):
    if profile == "app-store":
        raise PackageError(
            "App Store XPC transport and isolation acceptance are incomplete; "
            "a direct worker or renamed .xpc bundle cannot satisfy this profile. "
            "See docs/evx-platforms.md."
        )
    if profile != "direct-child":
        raise PackageError("unsupported EVX package profile")
    app, worker = worker_path(app)
    run_tool(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(worker)])
    run_tool(["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(app)])
    check_entitlements(run_tool([
        "/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(worker),
    ]))
    check_dependencies(run_tool(["/usr/bin/otool", "-L", str(worker)]))
    return {
        "profile": profile,
        "app_store_ready": False,
        "runtime_containment_verified": False,
        "worker": str(worker),
        "checks": ["placement", "signatures", "entitlements", "system_dependencies"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--profile", required=True, choices=("direct-child", "app-store"))
    args = parser.parse_args()
    try:
        result = verify(args.app, profile=args.profile)
    except (PackageError, OSError) as error:
        print(f"EVX package rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
