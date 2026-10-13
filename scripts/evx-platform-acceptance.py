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


def commands(profile):
    if profile == "linux":
        packages = ["evx-api", "evx-declaration", "evx-runtime", "evx-workspace",
                    "evx-activation", "evx-state", "evx-worker", "evx-supervisor",
                    "evx-host", "epix-evx"]
        native = ["cargo", "test"] + [arg for package in packages for arg in ("-p", package)]
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
        # This deliberately cannot claim a Windows worker or product sandbox.
        return [
            ("portable-core", ["cargo", "test", "-p", "evx-api", "-p", "evx-runtime",
                               "-p", "evx-activation", "-p", "evx-declaration", "--locked"]),
            ("pulley-core", ["cargo", "test", "-p", "evx-runtime", "--features", "pulley", "--locked"]),
            ("product-exclusion", [sys.executable, "scripts/check-evx-platforms.py",
                                   "windows-browser", "windows-server", "windows-nmh"]),
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
                result = subprocess.run(command, cwd=root, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=1800)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["linux", "windows-core"])
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
                "tests_native_worker_isolation": args.profile == "linux",
                "limits": "Tests only. Windows portable-core success does not enable EVX or verify OS isolation."}
    raise SystemExit(run_checks(commands(args.profile), ROOT, args.output, metadata, env))


if __name__ == "__main__":
    main()
