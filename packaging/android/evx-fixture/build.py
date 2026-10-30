#!/usr/bin/env python3
"""Build an unsigned, standalone fixture APK using an explicitly supplied SDK."""
import argparse
from pathlib import Path
import subprocess
import sys
import zipfile

HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--build-tools", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    jar = args.sdk / "platforms/android-36/android.jar"
    tools = args.sdk / "build-tools" / args.build_tools
    for path in [jar, tools / "aapt2", tools / "d8", tools / "zipalign"]:
        if not path.is_file(): parser.error(f"required SDK tool absent: {path}")
    args.output.mkdir(parents=True, exist_ok=False)
    classes = args.output / "classes"; classes.mkdir()
    dex = args.output / "dex"; dex.mkdir()
    subprocess.run([sys.executable, str(HERE / "check.py"), "--android-jar", str(jar)], check=True)
    sources = sorted((HERE / "src").rglob("*.java"))
    subprocess.run(["javac", "--release", "11", "-Xlint:all", "-Werror", "-classpath", str(jar), "-d", str(classes), *map(str, sources)], check=True)
    subprocess.run([str(tools / "d8"), "--min-api", "29", "--lib", str(jar), "--output", str(dex),
                    *map(str, sorted(classes.rglob("*.class")))], check=True)
    base = args.output / "base.apk"
    subprocess.run([str(tools / "aapt2"), "link", "--manifest", str(HERE / "AndroidManifest.xml"),
                    "-I", str(jar), "--min-sdk-version", "29", "--target-sdk-version", "36", "-o", str(base)], check=True)
    with zipfile.ZipFile(base, "a") as archive:
        for item in sorted(dex.glob("*.dex")): archive.write(item, item.name)
    apk = args.output / "evx-isolation-fixture-unsigned.apk"
    subprocess.run([str(tools / "zipalign"), "-p", "4", str(base), str(apk)], check=True)
    print(f"Unsigned development fixture: {apk}. Device signing and execution were not performed.")

if __name__ == "__main__": main()
