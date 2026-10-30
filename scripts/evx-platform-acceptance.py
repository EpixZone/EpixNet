#!/usr/bin/env python3
"""Run an explicit EVX platform test profile and retain command/source evidence."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NATIVE_PACKAGES = ["evx-api", "evx-declaration", "evx-runtime", "evx-workspace",
                   "evx-activation", "evx-state", "evx-worker", "evx-supervisor",
                   "evx-host", "epix-evx"]


def package_args(packages):
    return [arg for package in packages for arg in ("-p", package)]


def commands(profile, output=None):
    if profile == "linux":
        native = ["cargo", "test"] + package_args(NATIVE_PACKAGES)
        return [
            ("native", native + ["--locked"]),
            ("pulley", ["cargo", "test", "-p", "evx-runtime", "-p", "evx-worker",
                        "-p", "evx-supervisor", "-p", "evx-host", "--locked",
                        "--features", "evx-runtime/pulley"]),
            ("worker-build", ["cargo", "build", "-p", "evx-worker", "--locked"]),
            ("worker", [sys.executable, "packaging/linux/verify-evx-worker.py", "target/debug/evx-worker"]),
            ("privileged-worker", ["sudo", "-n", sys.executable, "packaging/linux/verify-evx-worker.py",
                                   "target/debug/evx-worker", "--require-privileged-parent"]),
            ("package", [sys.executable, "packaging/linux/test-evx-package.py", "-v"]),
        ]
    if profile == "windows-core":
        # The portable claim only: the runtime, the declaration and activation
        # logic, and the product dependency gates. The `windows` profile carries
        # the native evidence.
        return [
            ("portable-core", ["cargo", "test", "-p", "evx-api", "-p", "evx-runtime",
                               "-p", "evx-activation", "-p", "evx-declaration", "--locked"]),
            ("pulley-core", ["cargo", "test", "-p", "evx-runtime", "--features", "pulley", "--locked"]),
            ("product-gates", [sys.executable, "scripts/check-evx-platforms.py",
                               "windows-browser", "windows-server", "windows-nmh"]),
        ]
    if profile == "windows":
        # Native: every suite the node's backend depends on, inside real
        # AppContainers and Job Objects, plus the fixtures, the staged worker
        # image and the product dependency gates (docs/evx-windows-backend.md).
        examples = ROOT / "target/release/examples"
        worker_copy = (output or ROOT / "target") / "evx-worker-verified.exe"
        # Every test that spawns a child starts two or three AppContainer
        # processes, and the hosted Windows runner has four vCPUs with a
        # first-run Defender scan of each new image. Two tests at a time
        # keep the suites' fixed deadlines meaningful instead of measuring
        # the runner; the tests themselves are unchanged.
        threads = ["--", "--test-threads", str(WINDOWS_TEST_THREADS)]
        return [
            ("native", ["cargo", "test"] + package_args(NATIVE_PACKAGES) + ["--locked"] + threads),
            ("native-primitives", ["cargo", "test", "-p", "evx-windows-native", "-p", "evx-windows",
                                   "--lib", "--locked"] + threads),
            ("fixture-build", ["cargo", "build", "-p", "evx-windows", "--bins", "--example", "acceptance",
                               "--example", "execution_acceptance", "--release", "--locked"]),
            ("isolation", [str(examples / "acceptance.exe")]),
            ("execution", [str(examples / "execution_acceptance.exe")]),
            ("worker-build", ["cargo", "build", "-p", "evx-worker", "--locked"]),
            # Cargo hard-links the target binary; the verifier requires the
            # single-link shape a staged worker has, so verify a copy.
            ("worker-copy", [sys.executable, "-c", "import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])",
                             str(ROOT / "target/debug/evx-worker.exe"), str(worker_copy)]),
            ("worker", [sys.executable, "packaging/windows/verify-evx-worker.py", str(worker_copy), "--json"]),
            ("product-gates", [sys.executable, "scripts/check-evx-platforms.py",
                               "windows-browser", "windows-server", "windows-nmh"]),
            ("package", [sys.executable, "packaging/windows/test-evx-package.py", "-v"]),
        ]
    raise ValueError("unknown acceptance profile")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest(root):
    files = [root / "Cargo.toml", root / "Cargo.lock"]
    for crate in (root / "crates").iterdir():
        if crate.name.startswith("evx-") or crate.name == "epix-evx":
            files.extend(p for p in crate.rglob("*") if p.is_file()
                         and (p.suffix in {".rs", ".c", ".h"} or p.name == "Cargo.toml"))
    return {str(p.relative_to(root)): sha256(p) for p in sorted(files)}


def tool_version(command):
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


# Per-check wall budgets in seconds; the default covers a warm cache. The
# native suites compile the node's whole dependency graph on a cold runner.
TIMEOUTS = {"native": 5400, "fixture-build": 3600, "worker-build": 3600, "pulley": 3600}
# Concurrent tests in the Windows native suites (see the profile).
WINDOWS_TEST_THREADS = 2
DEFAULT_TIMEOUT = 1800


def run_checks(checks, root, output, metadata, env):
    output.mkdir(parents=True, exist_ok=False)
    record = dict(metadata, checks=[], completed=False)
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps(record, indent=2) + "\n")
    for name, command in checks:
        log = output / (name + ".log")
        started = time.monotonic()
        entry = {"name": name, "command": command,
                 "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            with log.open("w") as stream:
                # Closed stdin: a check that reads its input must fail, not
                # block on an inherited pipe until the budget runs out.
                result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                        stdout=stream, stderr=subprocess.STDOUT,
                                        timeout=TIMEOUTS.get(name, DEFAULT_TIMEOUT))
            entry["exit_code"] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            entry.update(exit_code=None, error=str(error))
        entry.update(elapsed_seconds=round(time.monotonic() - started, 3),
                     log_sha256=sha256(log))
        totals = re.findall(r"test result: ok\. (\d+) passed; \d+ failed; (\d+) ignored;",
                            log.read_text(errors="replace"))
        entry["passed"] = sum(int(item[0]) for item in totals)
        entry["ignored"] = sum(int(item[1]) for item in totals)
        record["checks"].append(entry)
        manifest.write_text(json.dumps(record, indent=2) + "\n")
        print(f"{name}: exit={entry['exit_code']}", flush=True)
        if entry["exit_code"] != 0:
            return 1
    record.update(completed=True, finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    manifest.write_text(json.dumps(record, indent=2) + "\n")
    return 0


LIMITS = {
    "linux": "Tests only. Linux native confinement evidence for the direct worker backend.",
    "windows-core": "Tests only. Windows portable-core success does not by itself verify OS isolation; "
                    "the windows profile does.",
    "windows": "Tests only. Windows native evidence: confined compile, run and file helpers through "
               "the supervisor, the LPAC and Job Object fixtures, and the staged worker image. "
               "The operator socket is absent on Windows (docs/evx-windows-backend.md).",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["linux", "windows-core", "windows"])
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory")
    args = parser.parse_args()
    required = "Linux" if args.profile == "linux" else "Windows"
    if platform.system() != required:
        parser.error(f"{args.profile} requires an actual {required} host")
    if os.environ.get("CARGO_TARGET_DIR"):
        parser.error("this profile requires the default target directory for its worker verifier")
    env = os.environ.copy()
    if args.profile == "linux":
        env["EVX_REQUIRE_LINUX_CONFINEMENT"] = "1"
    metadata = {"profile": args.profile, "platform": platform.platform(),
                "architecture": platform.machine(), "source_sha256": source_manifest(ROOT),
                "head": tool_version(["git", "rev-parse", "HEAD"]),
                "rustc": tool_version(["rustc", "--version", "--verbose"]),
                "cargo": tool_version(["cargo", "--version"]),
                "tests_native_worker_isolation": args.profile in ("linux", "windows"),
                "limits": LIMITS[args.profile]}
    raise SystemExit(run_checks(commands(args.profile, args.output), ROOT, args.output, metadata, env))


if __name__ == "__main__":
    main()
