#!/usr/bin/env python3
"""Run the production startup coordinator with real coroutines and a fake native node.

Set KOTLINC, JAVA_HOME and COROUTINES_JAR (kotlinx-coroutines-core-jvm 1.9.0).
No Android runtime, Gradle, native library or device is used.
"""
import os
import pathlib
import subprocess
import tempfile
import zipfile

root = pathlib.Path(__file__).resolve().parents[1]
coroutines = pathlib.Path(os.environ["COROUTINES_JAR"])
with zipfile.ZipFile(coroutines) as artifact:
    version = artifact.read("META-INF/kotlinx_coroutines_core.version").decode().strip()
    if version != "1.9.0":
        raise SystemExit(f"Expected kotlinx-coroutines-core-jvm 1.9.0, found {version}")

with tempfile.TemporaryDirectory(prefix="epix-node-host-tests-") as directory:
    test = pathlib.Path(directory)
    native = test / "NodeState.kt"
    native.write_text("package uniffi.epix_ffi\nenum class NodeState { IDLE, STARTING, SERVING, FAILED }\n")
    jar = test / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"],
        str(root / "app/src/main/java/zone/epix/app/StartupCoordinator.kt"),
        str(root / "tests/NodeHostRegressions.kt"), str(native),
        "-classpath", str(coroutines), "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"),
        "-cp", os.pathsep.join((str(jar), str(coroutines))),
        "zone.epix.app.NodeHostRegressionsKt",
    ], check=True, timeout=40)
