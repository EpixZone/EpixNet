#!/usr/bin/env python3
"""Execute the production SAF result callback with controlled document providers.

Set KOTLINC, JAVA_HOME and COROUTINES_JAR (1.9.0).
"""
import os
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
package = root / "app/src/main/java/zone/epix/app"
source = (package / "MainActivity.kt").read_text()
methods = re.findall(r"^    private fun handleDownloadResult\(.*?^    }", source, re.M | re.S)
assert len(methods) == 1
fixture = (root / "tests/run-download-result-regressions.kt").read_text()
fixture = fixture.replace("// INSERT_HANDLER", methods[0].replace("private fun", "fun", 1))
with tempfile.TemporaryDirectory(prefix="epix-download-result-") as directory:
    temp = pathlib.Path(directory)
    (temp / "Result.kt").write_text(fixture)
    (temp / "Log.kt").write_text("package android.util\nobject Log { fun w(tag: String, message: String, error: Throwable) {} }\n")
    jar = temp / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(package / "DownloadTransfer.kt"),
        str(package / "PendingOperations.kt"), str(temp / "Result.kt"), str(temp / "Log.kt"),
        "-classpath", os.environ["COROUTINES_JAR"], "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-cp",
        os.pathsep.join((str(jar), os.environ["COROUTINES_JAR"])), "zone.epix.app.ResultKt",
    ], check=True, timeout=20)
