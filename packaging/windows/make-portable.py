#!/usr/bin/env python3
"""Pack the staged Windows tree into the EpixNet Portable zip.

Usage: make-portable.py <stage-dir> <out.zip>

The zip holds one folder, "EpixNet Portable", with the staged files plus:

- the portable marker. Beside epix-browser.exe it makes the launcher keep
  everything in a Data folder there. It also explains the folder to users.
- a Firefox policy file for portable use. Firefox's own updater is off,
  because it downloads and schedules updates outside the folder. Users
  upgrade by replacing the folder, like the Linux AppImage. The launcher
  adds the CA's full path to this file at run time.

The staged exes are packed as they are, so a signed stage gives signed exes.
"""

import json
import sys
import zipfile
from pathlib import Path

TOP = "EpixNet Portable"
# Must match PORTABLE_MARKER in crates/epix-ui/src/paths.rs.
MARKER = "epixnet-portable.txt"
POLICIES = "firefox/distribution/policies.json"
REQUIRED = ("epix-browser.exe", "epix-nmh.exe", "evx-worker.exe", "firefox/firefox.exe", POLICIES)

MARKER_TEXT = """\
EpixNet Portable

This file turns on portable mode. EpixNet keeps everything in the Data
folder next to it: xites, keys, settings and the browser profile.
Nothing is installed.

Start EpixNet with epix-browser.exe.

To upgrade, quit EpixNet and unzip the new version. Then move this Data
folder into the new EpixNet Portable folder, and delete the old one.

To move EpixNet, quit it and move the whole folder.

The Data folder holds your private keys. Back it up and keep it safe.

Deleting this file turns portable mode off. EpixNet then uses its normal
per-user data folder.
"""


def portable_policies(staged: dict) -> dict:
    policies = dict(staged.get("policies", {}))
    # The launcher writes the CA's full path into Data at run time. The bare
    # filename would make Firefox look in the user's Mozilla folders.
    policies.pop("Certificates", None)
    policies["DisableAppUpdate"] = True
    return {**staged, "policies": policies}


def pack(stage: Path, out: Path) -> None:
    missing = [name for name in REQUIRED if not (stage / name).is_file()]
    if missing:
        raise SystemExit(f"stage {stage} is missing {', '.join(missing)}")
    if (stage / MARKER).exists() or (stage / "Data").exists():
        raise SystemExit(f"stage {stage} already holds portable files")
    staged = json.loads((stage / POLICIES).read_text(encoding="utf-8"))
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_name(out.name + ".partial")
    with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(stage.rglob("*")):
            relative = path.relative_to(stage).as_posix()
            if path.is_symlink():
                raise SystemExit(f"refusing to pack a symlink: {relative}")
            if path.is_dir() or relative == POLICIES:
                continue
            archive.write(path, f"{TOP}/{relative}")
        archive.writestr(
            f"{TOP}/{POLICIES}",
            json.dumps(portable_policies(staged), indent=2) + "\n",
        )
        archive.writestr(f"{TOP}/{MARKER}", MARKER_TEXT.replace("\n", "\r\n"))
    partial.replace(out)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: make-portable.py <stage-dir> <out.zip>")
    pack(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"portable zip: {sys.argv[2]}")


if __name__ == "__main__":
    main()
