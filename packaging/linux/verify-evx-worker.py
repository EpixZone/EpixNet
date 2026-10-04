#!/usr/bin/env python3
"""Execute confinement and compile/run fixtures against a built Linux worker.

This is a release/CI acceptance harness, not a node API. It uses only temporary
fixture data and refuses hosts without the required Landlock policy.
"""

import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import socket
import struct
import subprocess
import tempfile

MAX_FRAME = 131_072
MAX_ARTIFACT_FRAME = 262_144


def fixture_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024, 512 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))


def run(worker, mode, arguments=(), data=b""):
    # Regular temporary output files have a kernel size limit, so even an
    # unexpected binary cannot grow the harness's output buffers indefinitely.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(
            [str(worker), mode, *map(str, arguments)], input=data,
            stdout=stdout, stderr=stderr, env={}, timeout=25,
            preexec_fn=fixture_limits,
        )
        stdout.seek(0)
        stderr.seek(0)
        output, error = stdout.read(), stderr.read()
    if result.returncode != 0:
        raise RuntimeError(f"{mode} failed ({result.returncode}): {error[:4096]!r}")
    return output


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response key")
        result[key] = value
    return result


def frame(message, limit):
    body = json.dumps(message, separators=(",", ":")).encode()
    if len(body) > limit:
        raise ValueError("fixture exceeds input frame limit")
    return struct.pack(">I", len(body)) + body


def unframe(data, limit):
    if len(data) < 4:
        raise ValueError("missing response frame")
    length = struct.unpack(">I", data[:4])[0]
    if not 0 < length <= limit or len(data) != length + 4:
        raise ValueError("response frame limit or trailing output")
    return json.loads(data[4:], object_pairs_hook=unique_object)


def verify(worker, require_privileged_parent=False):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("requires a supported native Linux host")
    # These supported Linux architectures use the same Landlock syscall ID.
    abi = ctypes.CDLL(None, use_errno=True).syscall(444, None, 0, 1)
    if abi < 3:
        raise ValueError("Landlock ABI 3 or newer required for positive acceptance")
    capabilities = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
                        if line.startswith("CapEff:"))
    privileged_parent = bool(int(capabilities, 16) & (1 << 24))  # CAP_SYS_RESOURCE
    if require_privileged_parent and not privileged_parent:
        raise ValueError("privileged-parent regression requires CAP_SYS_RESOURCE")
    if worker.is_symlink() or not worker.is_file() or not os.access(worker, os.X_OK):
        raise ValueError("worker must be a regular executable")
    worker = worker.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="evx-package-probe-") as root:
        root = Path(root)
        workspace = root / "workspace"
        workspace.mkdir()
        outside = root / "outside.txt"
        outside.write_text("outside fixture")
        (workspace / "native-fixture.txt").write_text("fixture")
        (workspace / "outside-link").symlink_to(outside)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            probes = json.loads(run(worker, "probe", (
                outside, root / "must-not-exist", listener.getsockname()[1], workspace,
            )), object_pairs_hook=unique_object)
        wanted = {
            "outside_read", "outside_write", "workspace_read", "workspace_write",
            "workspace_truncate_readonly", "symlink_read", "etc_hosts_read",
            "home_listing", "loopback_connection", "network_bind", "subprocess_true",
            "fork", "raise_cpu_limit", "wasmtime_engine",
        }
        if len(probes) != len(wanted) or {row["op"] for row in probes} != wanted:
            raise ValueError("missing or duplicate native probe")
        for row in probes:
            if row["allowed"] != (row["op"] in {"workspace_read", "wasmtime_engine"}):
                raise ValueError(f"unexpected native authority: {row}")
            if row["op"] == "home_listing" and "Permission denied" not in row["detail"]:
                raise ValueError("home probe did not establish policy denial")
        if outside.read_text() != "outside fixture" or (workspace / "native-fixture.txt").read_text() != "fixture":
            raise ValueError("probe modified a protected fixture")
        if (root / "must-not-exist").exists() or (workspace / "native-probe.txt").exists():
            raise ValueError("probe created a forbidden file")

    source = b'(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 42))'
    compiled = unframe(run(worker, "compile", data=frame({
        "type": "compile_text", "source": base64.b64encode(source).decode(),
    }, MAX_FRAME)), MAX_ARTIFACT_FRAME)
    if compiled.get("type") != "artifact":
        raise ValueError(f"fixture compilation failed: {compiled}")
    artifact = base64.b64decode(compiled["artifact"], validate=True)
    if hashlib.sha256(artifact).hexdigest() != compiled["artifact_sha256"]:
        raise ValueError("compiler artifact digest mismatch")
    executed = unframe(run(worker, "run", data=frame({
        "type": "init", "artifact": compiled["artifact"],
        "artifact_sha256": compiled["artifact_sha256"],
        "limits": {
            "memory_bytes": 1024 * 1024, "fuel": 100_000, "host_calls": 16,
            "storage_bytes": 4096, "wall_seconds": 2.0, "host_call_seconds": 0.8,
            "process_cpu_seconds": 2.0, "process_rss_bytes": 128 * 1024 * 1024,
        },
    }, MAX_ARTIFACT_FRAME)), MAX_FRAME)
    if executed.get("type") != "result" or executed.get("status") != "ok" or executed.get("value") != 42:
        raise ValueError(f"confined computation failed: {executed}")
    return {
        "kernel": platform.release(), "architecture": platform.machine(),
        "landlock_abi": abi, "uid": os.getuid(),
        "parent_cap_sys_resource": privileged_parent,
        "worker_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
        "artifact_bytes": len(artifact), "native_probes": len(probes),
        "confined_computation": 42,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path, help="built or extracted packaged evx-worker")
    parser.add_argument("--require-privileged-parent", action="store_true",
                        help="require inherited CAP_SYS_RESOURCE for the capability-drop regression")
    args = parser.parse_args()
    print(json.dumps(verify(args.worker, args.require_privileged_parent), sort_keys=True))


if __name__ == "__main__":
    main()
