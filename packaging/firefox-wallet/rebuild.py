#!/usr/bin/env python3
"""Restore submitted Git provenance and compare an independent wallet rebuild."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile


def git(repository, *arguments, data=None):
    return subprocess.check_output(["git", "-C", str(repository), *arguments], input=data).strip().decode()


def source_path(repository, name):
    relative = PurePosixPath(name)
    path = repository / name
    if (relative.is_absolute() or ".." in relative.parts or "\\" in name
            or path.is_symlink() or not path.resolve().is_relative_to(repository.resolve())):
        raise ValueError("Source path escapes its repository")
    return path


def restore(root, metadata):
    for name, snapshot in metadata["repositories"].items():
        repository = source_path(root, name)
        if (repository / ".git").exists():
            raise ValueError("Restore requires newly extracted sources without existing Git metadata")
        git(repository, "init", "--quiet")
        index = bytearray()
        for entry in snapshot["files"]:
            path = source_path(repository, entry["path"])
            identity = git(repository, "hash-object", "-w", "--stdin", data=path.read_bytes())
            if identity != entry["blob"] or entry["mode"] not in ("100644", "100755"):
                raise ValueError("Extracted source differs from its original Git blob")
            path.chmod(0o755 if entry["mode"] == "100755" else 0o644)
            index.extend(f'{entry["mode"]} {identity}\t{entry["path"]}\0'.encode())
        git(repository, "update-index", "-z", "--index-info", data=bytes(index))
        tree = git(repository, "write-tree")
        commit = snapshot["commit"]
        if not commit.startswith(f"tree {tree}\n"):
            raise ValueError("Reconstructed source tree differs from its committed tree")
        identity = git(repository, "hash-object", "-w", "-t", "commit", "--stdin", data=commit.encode())
        if identity != snapshot["revision"]:
            raise ValueError("Commit metadata differs from the recorded revision")
        (repository / ".git/HEAD").write_text(identity + "\n")
        (repository / ".git/shallow").write_text(identity + "\n")
        if git(repository, "status", "--porcelain", "--untracked-files=normal"):
            raise ValueError("Restored source is not clean")
        print(f"Restored {name} at {identity}")


def submission_manifest(manifest, version):
    if "applications" in manifest:
        legacy = manifest.pop("applications")
        if "browser_specific_settings" in manifest and manifest["browser_specific_settings"] != legacy:
            raise ValueError("Firefox manifest contains conflicting browser settings")
        manifest["browser_specific_settings"] = legacy
    manifest["version"] = version
    return (json.dumps(manifest, indent=2) + "\n").encode()


def verify(entries, expected):
    actual = {name: hashlib.sha256(content).hexdigest() for name, content in entries.items()}
    different = sorted(name for name in actual.keys() | expected.keys() if actual.get(name) != expected.get(name))
    if different:
        raise ValueError("Rebuilt payload differs: " + ", ".join(different))
    print(f"Verified all {len(expected)} rebuilt files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("restore", "verify-wallet", "verify-final"))
    parser.add_argument("artifact", nargs="?", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    metadata = json.loads((root / "SOURCE.json").read_text())
    if args.operation == "restore":
        restore(root, metadata)
    elif args.artifact is None:
        parser.error("verification requires the rebuilt artifact path")
    elif args.operation == "verify-wallet":
        paths = list(args.artifact.rglob("*"))
        if any(path.is_symlink() for path in paths):
            raise ValueError("Rebuilt wallet contains symbolic links")
        entries = {path.relative_to(args.artifact).as_posix(): path.read_bytes() for path in paths if path.is_file()}
        verify(entries, metadata["wallet_files"])
    else:
        with zipfile.ZipFile(args.artifact) as archive:
            entries = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
        manifest = json.loads(entries["manifest.json"])
        entries["manifest.json"] = submission_manifest(manifest, metadata["version"])
        verify(entries, metadata["final_files"])


if __name__ == "__main__":
    main()
