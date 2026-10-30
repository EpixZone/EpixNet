#!/usr/bin/env python3
"""Run portable fixture tests, and require real iOS26 SDKs for adapter typechecking."""
import argparse
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-sdk", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="evx-ios-check-") as temporary:
        root = Path(temporary)
        core = HERE / "Shared/GameProtocol.swift"
        subprocess.run(["xcrun", "swiftc", "-swift-version", "6", "-warnings-as-errors", str(core),
                        str(HERE / "Tests/main.swift"), "-o", str(root / "core-tests")], check=True)
        subprocess.run([str(root / "core-tests")], check=True)
        if not args.require_sdk:
            print("iOS adapter typecheck not requested; use --require-sdk with Xcode26. Product EVX is disabled.")
            return
        for sdk, target in [("iphoneos", "arm64-apple-ios26.0"), ("iphonesimulator", "arm64-apple-ios26.0-simulator")]:
            version = subprocess.check_output(["xcrun", "--sdk", sdk, "--show-sdk-version"], text=True).strip()
            if int(version.split('.')[0]) < 26: raise RuntimeError(f"{sdk} SDK26 required, found {version}")
            path = subprocess.check_output(["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True).strip()
            for component in ["Host", "Helper"]:
                subprocess.run(["xcrun", "--sdk", sdk, "swiftc", "-swift-version", "6", "-warnings-as-errors",
                                "-parse-as-library", "-typecheck", "-sdk", path, "-target", target,
                                "-module-cache-path", str(root / "cache"), str(core),
                                *map(str, sorted((HERE / component).glob("*.swift")))], check=True)
            print(f"PASS {sdk} SDK {version} adapter typecheck; packaging/device execution not tested")

if __name__ == "__main__": main()
