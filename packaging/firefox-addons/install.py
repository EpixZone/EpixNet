#!/usr/bin/env python3
"""Stage fixed resources without changing Mozilla's original update inventory."""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
MODULE_FILES = ("chrome.manifest", "manager.sys.mjs", "policy.sys.mjs", "theme.sys.mjs", "manager.xhtml", "manager.css", "compatibility.json")

def install(resources: Path):
    if not resources.is_dir() or resources.is_symlink():
        raise ValueError("Firefox resources directory is missing or is a symbolic link")
    precomplete = resources / "precomplete"
    original = precomplete.read_bytes() if precomplete.exists() else None
    if original and any(name.encode() in original for name in ["epix-addons", "epix-addon-installer"]):
        raise ValueError("Firefox update inventory already contains custom installer resources")
    destination = resources / "distribution" / "epix-addon-installer"
    destination.mkdir(parents=True, exist_ok=True)
    for name in MODULE_FILES:
        shutil.copyfile(ROOT / name, destination / name)
    theme = destination / "theme"
    theme.mkdir(exist_ok=True)
    shutil.copyfile(ROOT.parent.parent / "shells" / "epix-theme" / "manifest.json", theme / "manifest.json")
    pref = resources / "defaults" / "pref"
    pref.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "epix-addons.js", pref / "epix-addons.js")
    shutil.copyfile(ROOT / "epix-addons.cfg", resources / "epix-addons.cfg")
    if original is not None and precomplete.read_bytes() != original:
        raise RuntimeError("Mozilla's update inventory changed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("resources", type=Path)
    install(parser.parse_args().resources)
