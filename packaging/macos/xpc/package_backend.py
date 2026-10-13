#!/usr/bin/env python3
"""Construct and verify signed development EVX service pools, without enabling release profiles."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("direct_package", HERE.parent / "verify-evx-package.py")
direct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(direct)
PackageError = direct.PackageError
PROFILE = "apple-xpc-development"
ROLES = ("guest", "compiler", "file")
SANDBOX = {"com.apple.security.app-sandbox": True}
INHERITED = {**SANDBOX, "com.apple.security.inherit": True}
MANIFEST = "evx-services.json"


def identifier(value):
    return isinstance(value, str) and len(value) <= 255 and re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def signing_info(path):
    result = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise PackageError("signature identity unavailable")
    text = result.stdout.decode("utf-8", errors="strict")
    name = re.search(r"^Identifier=(.+)$", text, re.M)
    code_hash = re.search(r"^CDHash=([0-9a-f]{40})$", text, re.M)
    if not name or not code_hash or not re.search(r"^Signature=adhoc$", text, re.M):
        raise PackageError("development package requires identifiable ad-hoc signatures")
    return name[1], code_hash[1]


def requirement(name, code_hash):
    return f'identifier "{name}" and cdhash H"{code_hash}"'


def sign(path, name, entitlements, directory):
    entitlement_file = directory / "signing-entitlements.plist"
    entitlement_file.write_bytes(plistlib.dumps(entitlements))
    direct.run_tool(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", name,
                     "--entitlements", str(entitlement_file), str(path)])
    entitlement_file.unlink()


def regular(path, executable=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
        raise PackageError(f"unsafe package file: {path.name}")
    if executable:
        if not info.st_mode & 0o111:
            raise PackageError("package executable is not executable")
        with path.open("rb") as stream:
            if stream.read(4) not in direct.MACHO_MAGIC:
                raise PackageError("package executable is not Mach-O")


def inspect_code(path, name, entitlements):
    direct.run_tool(["/usr/bin/codesign", "--verify", "--strict", str(path)])
    actual_name, code_hash = signing_info(path)
    if actual_name != name:
        raise PackageError("signed executable identifier mismatch")
    actual = plistlib.loads(direct.run_tool([
        "/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)]))
    if plistlib.dumps(actual, fmt=plistlib.FMT_BINARY) != plistlib.dumps(entitlements, fmt=plistlib.FMT_BINARY):
        raise PackageError("unexpected development executable entitlements")
    direct.check_dependencies(direct.run_tool(["/usr/bin/otool", "-L", str(path)]))
    return code_hash


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError("duplicate service-manifest key")
        result[key] = value
    return result


def read_plist(path):
    regular(path)
    if path.stat().st_size > 256 * 1024:
        raise PackageError("package plist exceeds limit")
    value = plistlib.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise PackageError("package plist must be a dictionary")
    return value


def verify(app):
    app = Path(os.path.abspath(app))
    for parent in (app, *app.parents):
        if parent.is_symlink():
            raise PackageError("symlink in package path")
    root_info = app.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_mode & 0o022 or root_info.st_uid not in (0, os.geteuid()):
        raise PackageError("unsafe app directory")
    for root, directories, files in os.walk(app, followlinks=False):
        for name in directories:
            info = (Path(root) / name).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in (0, os.geteuid()):
                raise PackageError("unsafe directory in package")
        for name in files:
            regular(Path(root) / name)
    manifest_path = app / "Contents" / "Resources" / MANIFEST
    regular(manifest_path)
    if manifest_path.stat().st_size > 128 * 1024:
        raise PackageError("service manifest exceeds limit")
    manifest = json.loads(manifest_path.read_text(), object_pairs_hook=unique_object)
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "profile", "host_identifier", "slots"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["profile"] != PROFILE or not identifier(manifest["host_identifier"])
            or not isinstance(manifest["slots"], list) or not 1 <= len(manifest["slots"]) <= 64):
        raise PackageError("unsupported service manifest")
    host_id = manifest["host_identifier"]
    info = read_plist(app / "Contents" / "Info.plist")
    if (info.get("CFBundleIdentifier") != host_id or info.get("CFBundleExecutable") != "host"
            or info.get("CFBundlePackageType") != "APPL" or info.get("LSMinimumSystemVersion") != "12.0"
            or info.get("EVXExecutionProfile") != PROFILE or info.get("EVXServiceManifest") != MANIFEST):
        raise PackageError("host manifest mismatch")
    if {p.name for p in (app / "Contents" / "MacOS").iterdir()} != {"host"}:
        raise PackageError("unexpected host executable")
    host = app / "Contents" / "MacOS" / "host"
    regular(host, True)
    inspect_code(host, host_id, SANDBOX)
    direct.run_tool(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    slots, services = set(), set()
    for slot in manifest["slots"]:
        if not isinstance(slot, dict) or set(slot) != {"slot", *ROLES} or not isinstance(slot.get("slot"), str) or not re.fullmatch(r"slot-[0-9]{3}", slot["slot"]):
            raise PackageError("invalid fixed slot")
        if slot["slot"] in slots:
            raise PackageError("duplicate slot")
        slots.add(slot["slot"])
        for role in ROLES:
            binding = slot[role]
            if not isinstance(binding, dict) or set(binding) != {"service", "requirement"} or not identifier(binding["service"]):
                raise PackageError("invalid role binding")
            name = binding["service"]
            if name.lower() in services or name != f"{host_id}.evx.{slot['slot']}.{role}":
                raise PackageError("service identity collision or wrong slot")
            services.add(name.lower())
            bundle = app / "Contents" / "XPCServices" / f"{name}.xpc"
            service = bundle / "Contents" / "MacOS" / "service"
            worker = service.with_name("evx-worker-apple")
            regular(service, True); regular(worker, True)
            service_info = read_plist(bundle / "Contents" / "Info.plist")
            if {p.name for p in service.parent.iterdir()} != {"service", "evx-worker-apple"}:
                raise PackageError("unexpected service executable")
            expected = {
                "CFBundleIdentifier": name, "CFBundleExecutable": "service", "CFBundlePackageType": "XPC!",
                "CFBundleVersion": "1", "XPCService": {"ServiceType": "Application", "RunLoopType": "dispatch_main", "JoinExistingSession": False},
                "EVXClientRequirement": f'identifier "{host_id}"', "EVXAuthorityHostIdentifier": host_id,
                "EVXWorkerSHA256": digest(worker), "EVXRole": role,
            }
            if plistlib.dumps(service_info, fmt=plistlib.FMT_BINARY) != plistlib.dumps(expected, fmt=plistlib.FMT_BINARY):
                raise PackageError("signed service configuration mismatch")
            code_hash = inspect_code(service, name, SANDBOX)
            if binding["requirement"] != requirement(name, code_hash):
                raise PackageError("service code hash mismatch")
            inspect_code(worker, host_id + ".evx.worker", INHERITED)
            direct.run_tool(["/usr/bin/codesign", "--verify", "--strict", str(bundle)])
    found = {path.stem.lower() for path in (app / "Contents" / "XPCServices").iterdir()}
    if found != services:
        raise PackageError("unexpected service bundle in pool")
    return {"profile": PROFILE, "app_store_ready": False, "runtime_containment_verified": False,
            "execution_enabled": False, "slots": len(slots), "services": len(services), "manifest": manifest}


def build(app, host, worker, service, host_identifier, slots=1):
    app = Path(app)
    if sys.platform != "darwin" or not identifier(host_identifier) or len(host_identifier) > 180:
        raise PackageError("macOS and a bounded host identifier are required")
    if type(slots) is not int or not 1 <= slots <= 64 or app.suffix != ".app" or app.exists() or app.is_symlink():
        raise PackageError("choose a new .app output and 1 to 64 slots")
    for binary in (host, worker, service):
        regular(Path(binary), True)
        direct.check_dependencies(direct.run_tool(["/usr/bin/otool", "-L", str(binary)]))
    parent = app.parent.resolve(strict=True)
    app = parent / app.name
    with tempfile.TemporaryDirectory(prefix=".evx-package-", dir=parent) as temporary:
        staging = Path(temporary)
        bundle = staging / app.name
        macos = bundle / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        shutil.copy2(host, macos / "host")
        signed_worker = staging / "worker"
        shutil.copy2(worker, signed_worker)
        sign(signed_worker, host_identifier + ".evx.worker", INHERITED, staging)
        worker_hash = digest(signed_worker)
        manifest = {"schema": 1, "profile": PROFILE, "host_identifier": host_identifier, "slots": []}
        for number in range(slots):
            entry = {"slot": f"slot-{number:03}"}
            for role in ROLES:
                name = f"{host_identifier}.evx.{entry['slot']}.{role}"
                nested = bundle / "Contents" / "XPCServices" / f"{name}.xpc"
                executable = nested / "Contents" / "MacOS" / "service"
                executable.parent.mkdir(parents=True)
                shutil.copy2(service, executable)
                shutil.copy2(signed_worker, executable.with_name("evx-worker-apple"))
                values = {"CFBundleIdentifier": name, "CFBundleExecutable": "service", "CFBundlePackageType": "XPC!", "CFBundleVersion": "1",
                          "XPCService": {"ServiceType": "Application", "RunLoopType": "dispatch_main", "JoinExistingSession": False},
                          "EVXClientRequirement": f'identifier "{host_identifier}"', "EVXAuthorityHostIdentifier": host_identifier,
                          "EVXWorkerSHA256": worker_hash, "EVXRole": role}
                (nested / "Contents" / "Info.plist").write_bytes(plistlib.dumps(values))
                sign(nested, name, SANDBOX, staging)
                entry[role] = {"service": name, "requirement": requirement(name, signing_info(executable)[1])}
            manifest["slots"].append(entry)
        resources = bundle / "Contents" / "Resources"
        resources.mkdir()
        (resources / MANIFEST).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        info = {"CFBundleIdentifier": host_identifier, "CFBundleExecutable": "host", "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
                "LSMinimumSystemVersion": "12.0", "EVXExecutionProfile": PROFILE, "EVXServiceManifest": MANIFEST}
        (bundle / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
        sign(bundle, host_identifier, SANDBOX, staging)
        verify(bundle)
        bundle.rename(app)
    return verify(app)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    make = commands.add_parser("build")
    for argument in ("app", "host", "worker", "service"):
        make.add_argument(argument, type=Path)
    make.add_argument("--host-identifier", required=True)
    make.add_argument("--slots", type=int, default=1)
    check = commands.add_parser("verify"); check.add_argument("app", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.app) if args.operation == "verify" else build(args.app, args.host, args.worker, args.service, args.host_identifier, args.slots)
    except (PackageError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Apple development package rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
