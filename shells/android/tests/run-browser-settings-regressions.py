#!/usr/bin/env python3
"""Execute the production browser-settings ordering with a controlled IO queue.

Set KOTLINC and JAVA_HOME. This extracts the pure store from EmbeddedNodeHost;
its queue and persistence callbacks are doubles, with no Android or native load.
"""
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / "app/src/main/java/zone/epix/app/EmbeddedNodeHost.kt").read_text()
marker = "internal class BrowserSettingsStore("
if source.count(marker) != 1:
    raise SystemExit("Expected exactly one production BrowserSettingsStore")
store = "package zone.epix.app\nimport java.util.concurrent.ConcurrentHashMap\n\n" + source[source.index(marker):]

with tempfile.TemporaryDirectory(prefix="epix-browser-settings-tests-") as directory:
    temporary = pathlib.Path(directory)
    production = temporary / "BrowserSettingsStore.kt"
    production.write_text(store)
    jar = temporary / "tests.jar"
    subprocess.run([
        os.environ["KOTLINC"], str(production),
        str(root / "tests/run-browser-settings-regressions.kt"),
        "-no-reflect", "-include-runtime", "-d", str(jar),
    ], check=True, timeout=90)
    subprocess.run([
        str(pathlib.Path(os.environ["JAVA_HOME"]) / "bin/java"), "-jar", str(jar),
    ], check=True, timeout=20)
