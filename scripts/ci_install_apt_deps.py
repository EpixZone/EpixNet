#!/usr/bin/env python3
"""Install CI prerequisites with bounded retries and hosted Ubuntu mirror fallback."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import time

ETC = Path("/etc")
MIRROR_URI = "mirror+file:/etc/apt/apt-mirrors.txt"
AZURE_URIS = {"http://azure.archive.ubuntu.com/ubuntu/", "https://azure.archive.ubuntu.com/ubuntu/"}
OFFICIAL_URI = "https://archive.ubuntu.com/ubuntu/"


def ubuntu_uses_mirror_list():
    legacy = ETC / "apt/sources.list"
    if legacy.is_file() and re.search(
        r"(?m)^\s*deb(?:-src)?\s+(?:\[[^]\n]*\]\s+)?" + re.escape(MIRROR_URI) + r"\s",
        legacy.read_text(),
    ):
        return True
    modern = ETC / "apt/sources.list.d/ubuntu.sources"
    if modern.is_file():
        for stanza in re.split(r"\n\s*\n", modern.read_text()):
            if re.search(r"(?im)^Enabled:\s*no\s*$", stanza):
                continue
            if re.search(r"(?m)^Types:\s*deb(?:-src)?(?:\s+deb(?:-src)?)*\s*$", stanza) and re.search(
                r"(?m)^URIs:\s*" + re.escape(MIRROR_URI) + r"\s*$", stanza
            ):
                return True
    return False


def use_official_mirrors():
    # Only the ephemeral amd64 runner layout is known here. Do not rewrite
    # developer/Debian/ARM sources or guess a codename, keyring, or ports URL.
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        return False
    os_release = ETC / "os-release"
    if not os_release.is_file() or not re.search(r'(?m)^ID=(?:ubuntu|"ubuntu")$', os_release.read_text()):
        return False
    arch = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, check=False)
    if arch.returncode or arch.stdout.strip() != "amd64" or not ubuntu_uses_mirror_list():
        return False
    mirror_list = ETC / "apt/apt-mirrors.txt"
    if not mirror_list.is_file() or mirror_list.is_symlink():
        return False
    lines = mirror_list.read_bytes().splitlines(keepends=True)
    uris = [line.split(maxsplit=1)[0].decode("ascii", errors="replace") if line.strip() else "" for line in lines]
    if OFFICIAL_URI not in uris or not AZURE_URIS.intersection(uris):
        return False
    # Keep all other bytes, priorities, sources and signature settings intact.
    # The file is shared by Ubuntu 22.04's sources.list and newer deb822 images.
    mirror_list.write_bytes(b"".join(line for line, uri in zip(lines, uris) if uri not in AZURE_URIS))
    print("::warning::Azure apt attempt failed; retrying with the runner's official Ubuntu mirrors", flush=True)
    return True


def install(packages):
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    for attempt in range(1, 3):
        for phase, arguments in (
            ("update", ["update"]),
            ("install", ["install", "-y", "--no-install-recommends", *packages]),
        ):
            result = subprocess.run(
                ["timeout", "--kill-after=15s", "300", "apt-get", *arguments], env=env, check=False
            )
            if result.returncode:
                print(f"::warning::apt {phase} attempt {attempt} failed with exit {result.returncode}", flush=True)
                break
        else:
            return 0
        if attempt == 1:
            use_official_mirrors()
            time.sleep(15)
    print("::error::apt prerequisites failed after 2 bounded attempts", flush=True)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run with sudo, preserving GITHUB_ACTIONS and RUNNER_ENVIRONMENT")
    return install(args.packages)


if __name__ == "__main__":
    raise SystemExit(main())
