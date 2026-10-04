#!/usr/bin/env python3
"""Fetch one pinned official API jar into a new temporary directory, without SDK installation."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads((HERE / "sdk-provenance.json").read_text())
    assert expected["url"] == "https://dl.google.com/android/repository/platform-36_r02.zip"
    args.output.mkdir(parents=True, exist_ok=False)
    with urllib.request.urlopen(expected["url"], timeout=60) as response:
        data = response.read(expected["bytes"] + 1)
    if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise RuntimeError("SDK archive size/digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [name for name in archive.namelist() if name.endswith("/android.jar")]
        if len(names) != 1 or archive.getinfo(names[0]).file_size != expected["android_jar_bytes"]:
            raise RuntimeError("unexpected API jar shape")
        jar = archive.read(names[0])
    if hashlib.sha256(jar).hexdigest() != expected["android_jar_sha256"]:
        raise RuntimeError("API jar digest mismatch")
    (args.output / "android.jar").write_bytes(jar)
    (args.output / "provenance.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(args.output / "android.jar")

if __name__ == "__main__": main()
