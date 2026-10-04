#!/usr/bin/env python3
"""Assemble Developer ID EVX services into an existing macOS host bundle.

This signs only the fixed service pool and outer host. The caller must sign all
other nested application code first. No signing identity is discovered or read.
"""
import argparse
import hashlib
import grp
import stat
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evx_development_package", HERE / "package_backend.py")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
PackageError = base.PackageError
PROFILE = "apple-xpc-developer-id"
FIXTURE = "apple-xpc-fixture"


def release_requirement(name, team):
    return (f'identifier "{name}" and anchor apple generic and '
            'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
            'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
            f'certificate leaf[subject.OU] = "{team}"')


def policy(team, identity, fixture):
    if fixture:
        if team or identity != "-":
            raise PackageError("fixture signing must be explicitly ad-hoc with no Team ID")
    elif not re.fullmatch(r"[A-Z0-9]{10}", team) or not identity or identity == "-":
        raise PackageError("release assembly needs an explicit Developer ID identity and ten-character Team ID")


def sign(path, identifier, entitlements, temporary, identity, fixture):
    values = temporary / "entitlements.plist"
    values.write_bytes(plistlib.dumps(entitlements))
    command = ["/usr/bin/codesign", "--force", "--sign", identity, "--identifier", identifier,
               "--entitlements", str(values)]
    if not fixture:
        command += ["--options", "runtime", "--timestamp"]
    base.direct.run_tool(command + [str(path)])
    values.unlink()


def code(path, identifier, entitlements, team, fixture):
    base.regular(path, True)
    base.direct.run_tool(["/usr/bin/codesign", "--verify", "--strict", str(path)])
    inspected = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(path)], capture_output=True, timeout=30)
    if inspected.returncode or len(inspected.stderr) > 1024 * 1024:
        raise PackageError("signature metadata unavailable")
    output = inspected.stderr.decode()
    name = re.search(r"^Identifier=(.+)$", output, re.M)
    digest = re.search(r"^CDHash=([0-9a-f]{40})$", output, re.M)
    if not name or name[1] != identifier or not digest:
        raise PackageError("code identity unavailable or mismatched")
    if fixture:
        if not re.search(r"^Signature=adhoc$", output, re.M):
            raise PackageError("fixture signature is not ad-hoc")
    else:
        if not re.search(rf"^TeamIdentifier={re.escape(team)}$", output, re.M) or "runtime" not in output:
            raise PackageError("release Team ID or hardened runtime missing")
        base.direct.run_tool(["/usr/bin/codesign", "--verify", "--strict", "-R", release_requirement(identifier, team), str(path)])
    actual = plistlib.loads(base.direct.run_tool(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(path)]))
    if plistlib.dumps(actual, fmt=plistlib.FMT_BINARY) != plistlib.dumps(entitlements, fmt=plistlib.FMT_BINARY):
        raise PackageError("unexpected executable entitlements")
    base.direct.check_dependencies(base.direct.run_tool(["/usr/bin/otool", "-L", str(path)]))
    return digest[1]


def host_build_policy(host, team):
    base.regular(host, True)
    if host.stat().st_size > 512 * 1024 * 1024:
        raise PackageError("host exceeds package limit")
    marker = b"EVX_PACKAGE_V1|apple-xpc|team=" + team.encode("ascii") + b"\0"
    if marker not in host.read_bytes():
        raise PackageError("host was not built with the matching Apple adapter and release Team ID")


def directory(path):
    info = path.lstat()
    writable = info.st_mode & 0o022
    sticky_system = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
    system_applications = (path == Path("/Applications") and info.st_uid == 0
                           and info.st_gid == grp.getgrnam("admin").gr_gid and writable == 0o020)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or (writable and not sticky_system and not system_applications)):
        raise PackageError("unsafe package directory")


def inspect_manifest(app, team, fixture):
    if not fixture and not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise PackageError("release verification requires explicit Team ID")
    app = Path(os.path.abspath(app))
    if any(parent.is_symlink() for parent in (app, *app.parents)):
        raise PackageError("symlink in app path")
    for parent in (app, *app.parents):
        directory(parent)
    for relative in ("Contents", "Contents/MacOS", "Contents/Resources", "Contents/XPCServices"):
        directory(app / relative)
    info = base.read_plist(app / "Contents/Info.plist")
    manifest_path = app / "Contents/Resources" / base.MANIFEST
    base.regular(manifest_path)
    if manifest_path.stat().st_size > 128 * 1024:
        raise PackageError("manifest exceeds limit")
    manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=base.unique_object)
    profile = FIXTURE if fixture else PROFILE
    if (not isinstance(manifest, dict) or set(manifest) != {"schema", "profile", "host_identifier", "team_identifier", "slots"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["profile"] != profile or manifest["team_identifier"] != team
            or not base.identifier(manifest["host_identifier"])
            or not isinstance(manifest["slots"], list) or not 1 <= len(manifest["slots"]) <= 64):
        raise PackageError("invalid release inventory")
    host_id = manifest["host_identifier"]
    if (info.get("CFBundleIdentifier") != host_id or info.get("EVXExecutionProfile") != profile
            or info.get("EVXServiceManifest") != base.MANIFEST
            or info.get("EVXServiceManifestSHA256") != base.digest(manifest_path)
            or info.get("EVXReleaseTeamIdentifier") != team
            or info.get("LSMinimumSystemVersion") != "12.0"):
        raise PackageError("sealed host policy mismatch")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", executable):
        raise PackageError("invalid host executable name")
    host_build_policy(app / "Contents/MacOS" / executable, team)
    code(app / "Contents/MacOS" / executable, host_id, {}, team, fixture)
    base.direct.run_tool(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    expected_services = set()
    for number, slot in enumerate(manifest["slots"]):
        if not isinstance(slot, dict) or set(slot) != {"slot", *base.ROLES} or slot["slot"] != f"slot-{number:03}":
            raise PackageError("noncanonical fixed slot")
        for role in base.ROLES:
            binding = slot[role]
            name = f"{host_id}.evx.{slot['slot']}.{role}"
            if not isinstance(binding, dict) or set(binding) != {"service", "requirement"} or binding["service"] != name:
                raise PackageError("role binding mismatch")
            expected_services.add(name + ".xpc")
            bundle = app / "Contents/XPCServices" / (name + ".xpc")
            if bundle.is_symlink() or not bundle.is_dir():
                raise PackageError("unsafe service bundle")
            main = bundle / "Contents/MacOS/service"
            worker = main.with_name("evx-worker-apple")
            for root, directories, files in os.walk(bundle, followlinks=False):
                directory(Path(root))
                for child_name in directories:
                    directory(Path(root) / child_name)
                for filename in files:
                    base.regular(Path(root) / filename)
            if {p.name for p in main.parent.iterdir()} != {"service", "evx-worker-apple"}:
                raise PackageError("unexpected service executable")
            client = f'identifier "{host_id}"' if fixture else release_requirement(host_id, team)
            expected = {"CFBundleIdentifier":name, "CFBundleExecutable":"service", "CFBundlePackageType":"XPC!", "CFBundleVersion":"1",
                        "XPCService":{"ServiceType":"Application", "RunLoopType":"dispatch_main", "JoinExistingSession":False},
                        "EVXClientRequirement":client, "EVXAuthorityHostIdentifier":host_id,
                        "EVXWorkerSHA256":base.digest(worker), "EVXRole":role}
            if base.read_plist(bundle / "Contents/Info.plist") != expected:
                raise PackageError("service policy mismatch")
            cdhash = code(main, name, base.SANDBOX, team, fixture)
            required = base.requirement(name, cdhash)
            if not fixture:
                required += " and " + release_requirement(name, team)
            if binding["requirement"] != required:
                raise PackageError("service signing requirement mismatch")
            code(worker, host_id + ".evx.worker", base.INHERITED, team, fixture)
    if {p.name for p in (app / "Contents/XPCServices").iterdir()} != expected_services:
        raise PackageError("unexpected service pool member")
    return {"profile":profile, "team_identifier":team, "slots":len(manifest["slots"]),
            "app_store_ready":False, "manifest":manifest}


def assemble(app, worker, service, team, identity, slots=16, fixture=False):
    policy(team, identity, fixture)
    app = Path(app)
    if sys.platform != "darwin" or app.is_symlink() or type(slots) is not int or not 1 <= slots <= 64:
        raise PackageError("macOS, a real bundle and 1 to 64 slots required")
    app = app.resolve(strict=True)
    info_path = app / "Contents/Info.plist"
    info = base.read_plist(info_path)
    host_id = info.get("CFBundleIdentifier")
    if not base.identifier(host_id) or len(host_id) > 180 or (app / "Contents/XPCServices").exists():
        raise PackageError("new service pool with bounded host identifier required")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", executable):
        raise PackageError("invalid host executable name")
    host_build_policy(app / "Contents/MacOS" / executable, team)
    for path in (worker, service):
        base.regular(Path(path), True)
    profile = FIXTURE if fixture else PROFILE
    manifest = {"schema":1, "profile":profile, "host_identifier":host_id, "team_identifier":team, "slots":[]}
    with tempfile.TemporaryDirectory(prefix="evx-release-sign-") as directory:
        temporary = Path(directory)
        signed_worker = temporary / "worker"
        shutil.copy2(worker, signed_worker)
        sign(signed_worker, host_id + ".evx.worker", base.INHERITED, temporary, identity, fixture)
        code(signed_worker, host_id + ".evx.worker", base.INHERITED, team, fixture)
        for number in range(slots):
            slot = {"slot":f"slot-{number:03}"}
            for role in base.ROLES:
                name = f"{host_id}.evx.{slot['slot']}.{role}"
                bundle = app / "Contents/XPCServices" / (name + ".xpc")
                main = bundle / "Contents/MacOS/service"
                main.parent.mkdir(parents=True)
                shutil.copy2(service, main)
                shutil.copy2(signed_worker, main.with_name("evx-worker-apple"))
                client = f'identifier "{host_id}"' if fixture else release_requirement(host_id, team)
                values = {"CFBundleIdentifier":name, "CFBundleExecutable":"service", "CFBundlePackageType":"XPC!", "CFBundleVersion":"1",
                          "XPCService":{"ServiceType":"Application", "RunLoopType":"dispatch_main", "JoinExistingSession":False},
                          "EVXClientRequirement":client, "EVXAuthorityHostIdentifier":host_id,
                          "EVXWorkerSHA256":base.digest(signed_worker), "EVXRole":role}
                (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(values))
                sign(bundle, name, base.SANDBOX, temporary, identity, fixture)
                cdhash = code(main, name, base.SANDBOX, team, fixture)
                required = base.requirement(name, cdhash)
                if not fixture:
                    required += " and " + release_requirement(name, team)
                slot[role] = {"service":name, "requirement":required}
            manifest["slots"].append(slot)
        resources = app / "Contents/Resources"
        resources.mkdir(exist_ok=True)
        manifest_path = resources / base.MANIFEST
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        info.update(EVXExecutionProfile=profile, EVXServiceManifest=base.MANIFEST,
                    EVXServiceManifestSHA256=base.digest(manifest_path), EVXReleaseTeamIdentifier=team,
                    LSMinimumSystemVersion="12.0")
        info_path.write_bytes(plistlib.dumps(info))
        sign(app, host_id, {}, temporary, identity, fixture)
    return inspect_manifest(app, team, fixture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    make = commands.add_parser("assemble")
    make.add_argument("app", type=Path); make.add_argument("worker", type=Path); make.add_argument("service", type=Path)
    make.add_argument("--identity", required=True); make.add_argument("--team-id", required=True)
    make.add_argument("--slots", type=int, default=16)
    check = commands.add_parser("verify"); check.add_argument("app", type=Path); check.add_argument("--team-id", required=True)
    args = parser.parse_args()
    try:
        result = (assemble(args.app, args.worker, args.service, args.team_id, args.identity, args.slots)
                  if args.operation == "assemble" else inspect_manifest(args.app, args.team_id, False))
    except (PackageError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"EVX release package rejected: {error}", file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True)); return 0

if __name__ == "__main__":
    sys.exit(main())
