#!/usr/bin/env python3
"""Exercise Homebrew artifact mirrors using an isolated prefix and no network route."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading

from package_mirror.server import make_server


def main(root, prefix):
    if not Path("/run/.containerenv").exists() or os.getuid() == 0:
        raise ValueError("Use an unprivileged user in a disposable container")
    if any(line.split()[1] == "00000000" for line in Path("/proc/net/route").read_text().splitlines()[1:]):
        raise ValueError("Use --network none")
    brew = prefix / "bin/brew"
    tap = prefix / "Homebrew/Library/Taps/epix/homebrew-fixture"
    formula = tap / "Formula/epix-mirror-fixture.rb"
    formula.parent.mkdir(parents=True)
    subprocess.run(["git", "init", tap], check=True)
    env = dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_INSTALL_FROM_API="1",
               HOMEBREW_NO_ANALYTICS="1", HOMEBREW_NO_INSTALL_CLEANUP="1", HOMEBREW_NO_ENV_HINTS="1",
               HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK="1")
    results = {"client": "Homebrew", "network": "container none", "versions": []}
    for version in ("1.0", "2.0"):
        snapshot = root / f"exported-homebrew-ghcr-{version}"
        if not (snapshot / "epix-export.json").exists():
            raise ValueError("Fixture must pass through the real node's verified ZIP export")
        filename = f"epix-mirror-fixture-{version}.tar.gz"
        digest = hashlib.sha256((snapshot / "repo" / filename).read_bytes()).hexdigest()
        formula.write_text(f'''class EpixMirrorFixture < Formula
  desc "Disposable offline mirror fixture"
  homepage "https://mirror-fixture.invalid/"
  url "https://ghcr.io/v2/epix/fixture/blobs/sha256:{digest}"
  version "{version}"
  sha256 "{digest}"
  license "MIT"
  env :std
  def install
    bin.install "epix-mirror-fixture"
  end
end
''')
        subprocess.run(["git", "-C", tap, "add", "."], check=True)
        subprocess.run(["git", "-C", tap, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "-m", "Fixture " + version], check=True)
        server = make_server(snapshot, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env["HOMEBREW_ARTIFACT_DOMAIN"] = f"http://127.0.0.1:{server.server_port}"
        try:
            operation = "install" if version == "1.0" else "upgrade"
            subprocess.run([brew, operation, "--build-from-source", "epix/fixture/epix-mirror-fixture"], env=env, check=True)
            actual = subprocess.check_output([prefix / "bin/epix-mirror-fixture"], text=True).strip()
            if actual != version:
                raise ValueError(f"Expected {version}, got {actual}")
            results["versions"].append(actual)
            if version == "2.0":
                formula.write_text(formula.read_text().replace(f'sha256 "{digest}"', 'sha256 "' + "0" * 64 + '"'))
                rejected = subprocess.run([brew, "fetch", "--force", "epix/fixture/epix-mirror-fixture"],
                                          env=env, capture_output=True, text=True)
                print(rejected.stdout + rejected.stderr, flush=True)
                if rejected.returncode == 0 or "checksum" not in (rejected.stdout + rejected.stderr).lower():
                    raise ValueError("Homebrew did not reject the incorrect formula checksum")
                results["incorrect_upstream_checksum_rejected"] = True
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    results["brew_revision"] = subprocess.check_output(["git", "-C", prefix / "Homebrew", "rev-parse", "HEAD"], text=True).strip()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, default=Path("/home/linuxbrew/.linuxbrew"))
    arguments = parser.parse_args()
    main(arguments.root, arguments.prefix)
