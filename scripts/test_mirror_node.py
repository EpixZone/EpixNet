#!/usr/bin/env python3
"""Sign disposable staged fixtures and export them through a real EpixNet node.

Run in a network namespace with only loopback, never against a personal node.
The server binary must come from the checkout being tested. Fixtures are made
by test_mirror_clients.py in a disposable container first.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
import urllib.request

from package_mirror.snapshot import export


def main(binary, fixtures, output):
    if os.name != "posix" or sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        raise ValueError("Use an isolated Linux network namespace with only loopback")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    if output.exists():
        raise ValueError("QA output must be a new disposable directory")
    output.mkdir(parents=True)
    root = output / "node"
    (root / "private").mkdir(parents=True)
    (root / "private/config.json").write_text(json.dumps({"open_browser": False, "fileserver_port": 0,
        "trackers": [], "trackers_file": [], "tor": "disable", "local_discovery": False, "mesh": False}))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    env = dict(os.environ, EPIX_DATA_DIR=str(root.absolute()), EPIX_HEADLESS="1", EPIX_TOR="disable",
               EPIX_UI_ADDR=f"127.0.0.1:{port}")
    addresses = {}
    for source in sorted(fixtures.glob("snapshot-*")):
        label = source.name.removeprefix("snapshot-")
        # siteCreate prints the disposable owner key. Do not save or print it.
        created = subprocess.run([binary, "siteCreate"], env=env, capture_output=True, text=True, check=True)
        address = re.search(r"Xite address:\s+(epix1\w+)", created.stdout)[1]
        target = root / "data" / address
        shutil.copy2(source / "epix-mirror.json", target / "epix-mirror.json")
        shutil.copytree(source / "repo", target / "repo")
        with (output / f"sign-{label}.log").open("w") as log:
            subprocess.run([binary, "siteSign", address, "--full"], env=env, check=True, stdout=log, stderr=log)
        addresses[label] = address
    if not addresses:
        raise ValueError("No staged fixture snapshots")
    with (output / "node.log").open("w") as log:
        process = subprocess.Popen([binary, next(iter(addresses.values()))], env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    with urllib.request.urlopen(origin + "/StatsJson", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Disposable node did not become ready") from None
                    time.sleep(0.1)
            results = {}
            for label, address in addresses.items():
                catalog = export(origin, address, fixtures / f"exported-{label}")
                results[label] = {"address": address, "snapshot": catalog["snapshot"], "files": len(catalog["files"])}
            (output / "exports.json").write_text(json.dumps(results, indent=2))
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-binary", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    main(args.node_binary.absolute(), args.fixtures.absolute(), args.output.absolute())
