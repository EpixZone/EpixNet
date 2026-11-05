#!/usr/bin/env python3
"""Run production download stream ownership and cancellation with real JVM IO.

Set KOTLINC and JAVA_HOME. No Android framework or network is needed.
"""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="epix-download-tests-") as directory:
    jar = pathlib.Path(directory) / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"],
        str(root / "app/src/main/java/zone/epix/app/DownloadTransfer.kt"),
        str(root / "tests/run-download-regressions.kt"),
        "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(jar),
    ], check=True, timeout=20)
