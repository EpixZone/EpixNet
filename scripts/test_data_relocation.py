#!/usr/bin/env python3
"""Run the actual relocation module and path tests without building the browser."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))

    def version(name, prefix):
        found = [p["version"] for p in lock["package"]
                 if p["name"] == name and p["version"].startswith(prefix)]
        if len(found) != 1:
            raise RuntimeError(f"Expected one locked {name} {prefix} version, found {found}")
        return "=" + found[0]

    def quoted(value):
        return json.dumps(str(value), ensure_ascii=False)

    with tempfile.TemporaryDirectory(prefix="epix-relocation-tests-") as scratch:
        harness = Path(scratch)
        lines = ["[package]", 'name="epix-relocation-validation"', 'version="0.0.0"',
                 'edition="2021"', "[workspace]", "[lib]", 'path="lib.rs"', "[dependencies]"]
        for name, prefix in [("serde_json", "1."), ("getrandom", "0.4."), ("hex", "0.4."), ("libc", "0.2.")]:
            lines.append(f"{name}={quoted(version(name, prefix))}")
        lines += [f'serde={{version={quoted(version("serde", "1."))},features=["derive"]}}',
                  f'epix-fs={{path={quoted(root / "crates/epix-fs")}}}',
                  "[target.'cfg(unix)'.dependencies]",
                  f'rustix={{version={quoted(version("rustix", "1.1."))},features=["fs"]}}',
                  "[target.'cfg(windows)'.dependencies]",
                  f'windows-sys={{version={quoted(version("windows-sys", "0.61."))},features=["Win32_Storage_FileSystem","Win32_Foundation","Win32_Security","Win32_Security_Authorization","Win32_System_Threading", "Win32_System_SystemServices"]}}',
                  "[dev-dependencies]",
                  f'tempfile={quoted(version("tempfile", "3."))}',
                  f'rusqlite={{version={quoted(version("rusqlite", "0.37."))},features=["bundled"]}}']
        (harness / "Cargo.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        # Reuse the repository's checksummed transitive resolutions. Cargo adds
        # only this tiny harness package; the repository lock is never changed.
        shutil.copyfile(root / "Cargo.lock", harness / "Cargo.lock")
        modules = "".join(f'#[path={quoted(root / "crates/epix-ui/src" / (name + ".rs"))}]\npub mod {name};\n'
                          for name in ["paths", "data_relocation"])
        (harness / "lib.rs").write_text(modules, encoding="utf-8")
        environment = os.environ.copy()
        environment["CARGO_BUILD_JOBS"] = "2"
        environment["CARGO_TARGET_DIR"] = str(args.target_dir.resolve() if args.target_dir else harness / "target")
        command = ["cargo", "test", "--manifest-path", str(harness / "Cargo.toml")]
        if args.offline:
            command.append("--offline")
        command += ["--", "--test-threads=2"]
        subprocess.run(command, cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
