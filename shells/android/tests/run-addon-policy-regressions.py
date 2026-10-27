#!/usr/bin/env python3
"""Compile actual native extension policy/lifecycle without an Android runtime."""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="epix-addon-tests-") as temporary:
    jar = pathlib.Path(temporary) / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"],
        str(root / "app/src/main/java/zone/epix/app/AddonPolicy.kt"),
        str(root / "app/src/main/java/zone/epix/app/AddonProfile.kt"),
        str(root / "app/src/main/java/zone/epix/app/AddonEngineFiles.kt"),
        str(root / "tests/run-addon-policy-regressions.kt"),
        str(root / "tests/run-addon-engine-files-regressions.kt"),
        "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    java = pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"
    subprocess.run([str(java), "-jar", str(jar)], check=True, timeout=30)
