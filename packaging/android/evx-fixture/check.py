#!/usr/bin/env python3
"""Compile the fixed fixture against an explicit official android.jar; never installs an SDK."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--android-jar", type=Path)
    args = parser.parse_args()
    sources = HERE / "src/zone/epix/evxfixture"
    with tempfile.TemporaryDirectory(prefix="evx-android-check-") as temporary:
        out = Path(temporary)
        subprocess.run(["javac", "--release", "11", "-Xlint:all", "-Werror", "-d", str(out),
                        str(sources / "GameProtocol.java"), str(sources / "InvocationState.java"),
                        str(HERE / "tests/ProtocolTest.java")], check=True)
        subprocess.run(["java", "-cp", str(out), "zone.epix.evxfixture.ProtocolTest"], check=True)
        ns = "{http://schemas.android.com/apk/res/android}"
        manifest = ET.parse(HERE / "AndroidManifest.xml").getroot()
        assert not manifest.findall("uses-permission")
        service = manifest.find("application/service")
        assert service.get(ns + "isolatedProcess") == "true" and service.get(ns + "exported") == "false"
        assert service.get(ns + "useAppZygote") == "false"
        if args.android_jar:
            subprocess.run(["javac", "--release", "11", "-Xlint:all", "-Werror", "-classpath", str(args.android_jar),
                            "-d", str(out), *map(str, sorted(sources.glob("*.java")))], check=True)
            print(json.dumps({"android_api_typecheck":"passed", "android_jar_sha256":hashlib.sha256(args.android_jar.read_bytes()).hexdigest(),
                              "device_execution":"not_run"}))
        else:
            print("Android API typecheck not run: pass --android-jar. Product EVX remains disabled.")

if __name__ == "__main__": main()
